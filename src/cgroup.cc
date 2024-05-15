////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2012-2015 Jun Wu <quark@zju.edu.cn>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
////////////////////////////////////////////////////////////////////////////////

#include <cstdio>
#include <cstring>
#include <list>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <climits>
#include "cgroup.h"
#include "utils/linux_only.h"
#include "utils/for_each.h"
#include "utils/fs.h"
#include "utils/strconv.h"


using namespace lrun;

using std::string;
using std::list;

static struct {
    const char *name;
    unsigned int minor;
    // major is missing because all basic_devices have major = 1
} basic_devices[] = {
    {"null", 3},
    {"zero", 5},
    {"full", 7},
    {"random", 8},
    {"urandom", 9},
};

// following functions are called by clone_main_fn

__attribute__((unused)) static void do_set_sysctl() {
    INFO("set sysctl settings");
    // skip slow oom scaning and do not write syslog
    fs::write("/proc/sys/vm/oom_kill_allocating_task", "1\n");
    fs::write("/proc/sys/vm/oom_dump_tasks", "0\n");
    // block dmesg access
    fs::write("/proc/sys/kernel/dmesg_restrict", "1\n");
}

static void do_privatize_filesystem(__attribute__((unused)) const Cgroup::spawn_arg& arg) {
    // make sure filesystem not be shared
    // ignore this step for old systems without these features
    int type = MS_PRIVATE | MS_REC;
    if (type && fs::mount_set_shared("/", MS_PRIVATE | MS_REC)) {
        FATAL("can not mount --make-rprivate /");
    }
}

static void do_remounts(const Cgroup::spawn_arg& arg) {
    FOR_EACH(p, arg.remount_list) {
        const string& dest = p.first;
        unsigned long flags = p.second;
        // tricky point: if the original mount point has --bind, remount with --bind
        // can make it less likely to get "device busy" message
        if (arg.bindfs_dest_set.count(dest)) flags |= MS_BIND;

        INFO("remount %s", dest.c_str());
        for (;;) {
            if (fs::remount(dest, flags) == 0) break;
            if (flags & MS_BIND) FATAL("remount '%s' failed", dest.c_str());
            flags |= MS_BIND;
        }
    }
}

static void do_mount_bindfs(const Cgroup::spawn_arg& arg) {
    // bind fs mounts
    FOR_EACH(p, arg.bindfs_list) {
        const string& dest = p.first;
        const string& src = p.second;

        INFO("mount bind %s -> %s", src.c_str(), dest.c_str());
        if (fs::mount_bind(src, dest)) {
            FATAL("mount bind '%s' -> '%s' failed", src.c_str(), dest.c_str());
        }
    }
}

static void do_chroot(const Cgroup::spawn_arg& arg) {
    // chroot to a prepared place
    if (!arg.chroot_path.empty()) {
        const string& path = arg.chroot_path;

        INFO("chroot %s", path.c_str());
        if (chroot(path.c_str())) {
            FATAL("chroot '%s' failed", path.c_str());
        }
    }
}

static void do_umount_outside_chroot(const Cgroup::spawn_arg& arg) {
    if (!arg.umount_outside) return;
    if (arg.chroot_path.empty()) return;

    std::map<string, fs::MountEntry> mounts = fs::get_mounts();
    list<string> umount_list;
    FOR_EACH(p, mounts) {
        const string& dest = p.second.dir;
        if (arg.chroot_path.substr(0, dest.length()) == dest) continue;
        if (dest.substr(0, arg.chroot_path.length()) == arg.chroot_path) continue;
        umount_list.push_front(dest);
    }

    // umount in reversed order
    FOR_EACH(dest, umount_list) {
        INFO("umount %s", dest.c_str());
        if (umount2(dest.c_str(), MNT_DETACH) == -1) {
            WARNING("cannot umount %s", dest.c_str());
        }
    }
}

static bool should_mount_proc(const Cgroup::spawn_arg& arg) {
    if (!fs::is_accessible(fs::join(arg.chroot_path, fs::PROC_PATH), X_OK)) return false;
    return (arg.clone_flags & CLONE_NEWPID) != 0 || !arg.chroot_path.empty();
}

static bool should_hide_sensitive(const Cgroup::spawn_arg& arg) {
    if (!should_mount_proc(arg)) return false;

    // currently there is no option about this behavior
    // when `--no-new-privs false`, the user does not want to hide anything
    if (!arg.no_new_privs) return false;
    if (getenv("LRUN_DO_NOT_HIDE_SENSITIVE")) return false;
    return true;
}

static const char * get_proc_fs_type(const Cgroup::spawn_arg& arg) {
    // use "liteproc" when possible
    static const char proc_fs[] = "proc";
    static const char liteproc_fs[] = "liteproc";
    // when `--no-new-privs false`, the user does not want to hide anything
    if (!arg.no_new_privs) return proc_fs;
    // 4KB is probably enough for /proc/filesystems.
    // on my system, it is 398 bytes now.
    if (fs::read("/proc/filesystems", 4095).find("liteproc") == string::npos) {
        return proc_fs;
    } else {
        return liteproc_fs;
    }
}

static void do_mount_proc(const Cgroup::spawn_arg& arg) {
    // mount /proc if pid namespace is enabled and the directory exists
    if (!should_mount_proc(arg)) return;
    string dest = fs::join(arg.chroot_path, fs::PROC_PATH);
    INFO("mount procfs at %s", dest.c_str());
    const char * mount_opts = should_hide_sensitive(arg) ? "hidepid=2" : NULL;
    if (mount(NULL, dest.c_str(), get_proc_fs_type(arg), MS_NOEXEC | MS_NOSUID, mount_opts)) {
        FATAL("mount procfs failed");
    }
}

static void do_hide_sensitive(const Cgroup::spawn_arg& arg) {
    if (!should_hide_sensitive(arg)) return;
    string proc_sys_path = fs::join(arg.chroot_path, "/proc/sys");
    if (fs::is_accessible(proc_sys_path, X_OK)) {
        mount(NULL, proc_sys_path.c_str(), "tmpfs", MS_NOSUID | MS_RDONLY, "size=0");
    }
}

static list<int> get_fds() {
    list<int> fds;

    struct dirent **namelist = 0;
    int nlist = scandir("/proc/self/fd", &namelist, 0, alphasort);
    for (int i = 0; i < nlist; ++i) {
        const char * name = namelist[i]->d_name;
        // skip . and ..
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            int fd = -1;
            if (sscanf(name, "%d", &fd) != 1) continue;
            // scandir will use a dirfd. verify existance of fds
            if (fs::is_fd_valid(fd))
                fds.push_back(fd);
        }
        free(namelist[i]);
    }
    if (namelist) free(namelist);

    return fds;
}

static void do_set_uts(const Cgroup::spawn_arg& arg) {
    int e;
    if (!arg.uts.domainname.empty()) {
        INFO("setdomainname: %s", arg.uts.domainname.c_str());
        e = setdomainname(arg.uts.domainname.c_str(), arg.uts.domainname.length());
        if (e == -1) {
            FATAL("setdomainname '%s' failed", arg.uts.domainname.c_str());
            exit(-1);
        }
    }
    if (!arg.uts.nodename.empty()) {
        INFO("sethostname: %s", arg.uts.nodename.c_str());
        e = sethostname(arg.uts.nodename.c_str(), arg.uts.nodename.length());
        if (e == -1) {
            FATAL("sethostname '%s' failed", arg.uts.nodename.c_str());
            exit(-1);
        }
    }

    // [[[cog
    //  import cog
    //  opts = {'release': 'osrelease', 'sysname': 'ostype', 'version': 'version'}
    //  for opt, name in opts.items():
    //    cog.out('''
    //      if (!arg.uts.%(opt)s.empty() && fs::is_accessible("/proc/sys/utsmod/%(name)s"), W_OK) {
    //          fs::write("/proc/sys/utsmod/%(name)s", arg.uts.%(opt)s);
    //      }''' % {'name': name, 'opt': opt}, trimblanklines=True)
    // ]]]
    if (!arg.uts.release.empty() && fs::is_accessible("/proc/sys/utsmod/osrelease"), W_OK) {
        fs::write("/proc/sys/utsmod/osrelease", arg.uts.release);
    }
    if (!arg.uts.sysname.empty() && fs::is_accessible("/proc/sys/utsmod/ostype"), W_OK) {
        fs::write("/proc/sys/utsmod/ostype", arg.uts.sysname);
    }
    if (!arg.uts.version.empty() && fs::is_accessible("/proc/sys/utsmod/version"), W_OK) {
        fs::write("/proc/sys/utsmod/version", arg.uts.version);
    }
    // [[[end]]]
}

static void do_set_netns(const Cgroup::spawn_arg& arg) {
    if (arg.netns_fd == -1) return;

    INFO("set netns")

    // older glibc does not have setns
    if (syscall(SYS_setns, arg.netns_fd, CLONE_NEWNET)) {
        FATAL("can not set netns");
    };
}

static void do_fd_redirect(int fd_dst, int fd_src) {
    if (fd_src >= 0 && fd_src != fd_dst) {
        INFO("dup2 %d %d", fd_src, fd_dst);
        int ret = dup2(fd_src, fd_dst);
        if (ret == -1) {
            FATAL("cannot dup %d", fd_src);
        }
    }
}

static void fd_set_cloexec(int fd, int enforce = 1) {
    if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC)) {
        if (enforce) {
            FATAL("fcntl %d failed", fd);
        } else {
            // fd can become invalid across namespaces
            close(fd);
        }
    }
}

static void do_process_fds(const Cgroup::spawn_arg& arg) {
    // this is for parent process
    close(arg.sockets[1]);

#ifndef NDEBUG
    // make a copy of log fd because we may soon lose stderr
    // this affects INFO, WARN, ERROR, FATAL
    int flog_fd = dup(STDERR_FILENO);
    flog = fdopen(flog_fd, "a");
#endif

    do_fd_redirect(STDOUT_FILENO, arg.stdout_fd);
    do_fd_redirect(STDERR_FILENO, arg.stderr_fd);

    INFO("applying FD_CLOEXEC");
    list<int> fds = get_fds();
    FOR_EACH(fd, fds) {
        if (fd != STDERR_FILENO && fd != STDIN_FILENO && fd != STDOUT_FILENO
                && arg.keep_fds.count(fd) == 0) {
            fd_set_cloexec(fd, 0 /* close that fd on error */);
        }
    }
}

static void do_mount_tmpfs(const Cgroup::spawn_arg& arg) {
    // setup other tmpfs mounts
    FOR_EACH(p, arg.tmpfs_list) {
        const char * dest = p.first.c_str();
        const long long& size = p.second;

        INFO("mount tmpfs %s (size = %lld kB)", dest, size);

        int e = 0;
        if (size <= 0) {
            // treat as read-only
            e = mount(NULL, dest, "tmpfs", MS_NOSUID | MS_RDONLY, "size=0");
        } else {
            e = mount(NULL, dest, "tmpfs", MS_NOSUID, ((string)("mode=0777,size=" + strconv::from_longlong(size))).c_str());
        }
        if (e) {
            FATAL("mount tmpfs '%s' failed", dest);
        }
    }
}

static void do_remount_dev(const Cgroup::spawn_arg& arg) {
    if (!arg.remount_dev) return;

    INFO("remount /dev");

    int e;
    // mount a minimal tmpfs to /dev
    e = mount(NULL, "/dev", "tmpfs", MS_NOSUID, "size=64,mode=0755,uid=0,gid=0");
    if (e) FATAL("remount /dev failed");

    // create basic devices
    for (size_t i = 0; i < sizeof(basic_devices) / sizeof(basic_devices[0]); ++i) {
        string path = string("/dev/") + basic_devices[i].name;
        unsigned int minor = basic_devices[i].minor;
        e = mknod(path.c_str(), S_IFCHR | 0666 /* mode */, makedev(1 /* major */, minor));
        if (!e) e = chmod(path.c_str(), 0666);
        if (e) FATAL("failed to create dev: '%s'", path.c_str());
    }
}

static void do_chdir(const Cgroup::spawn_arg& arg) {
    // chdir to a specified path
    if (!arg.chdir_path.empty()) {
        const string& path = arg.chdir_path;

        INFO("chdir %s", path.c_str());
        if (chdir(path.c_str())) {
            FATAL("chdir '%s' failed", path.c_str());
        }
    }
}

static void do_commands(const Cgroup::spawn_arg& arg) {
    // system commands
    FOR_EACH(cmd, arg.cmd_list) {
        INFO("system %s", cmd.c_str());
        int ret = system(cmd.c_str());
        if (ret) WARNING("system \"%s\" returns %d", cmd.c_str(), ret);
    }
}

static void do_renice(const Cgroup::spawn_arg& arg) {
    // nice
    if (arg.nice) {
        INFO("nice %d", (int)arg.nice);
        if (nice(arg.nice) == -1) {
            WARNING("can not set nice to %d", arg.nice);
        }
    }
}

static void do_set_umask(const Cgroup::spawn_arg& arg) {
    // set umask
    INFO("umask %d", arg.umask);
    umask(arg.umask);
}

static void do_set_uid_gid(const Cgroup::spawn_arg& arg) {
    // setup uid, gid
    INFO("setgid %d, setuid %d", (int)arg.gid, (int)arg.uid);
    if (setgid(arg.gid) || setuid(arg.uid)) {
        // an interesting story about not checking setuid return value:
        // https://sites.google.com/site/fullycapable/Home/thesendmailcapabilitiesissue
        FATAL("setgid(%d) or setuid(%d) failed", (int)arg.gid, (int)arg.uid);
    }
}

static void do_apply_rlimits(const Cgroup::spawn_arg& arg) {
    // apply rlimit, note NPROC limit should be applied after setuid
    FOR_EACH(p, arg.rlimits) {
        int resource = p.first;
        if (resource >= RLIMIT_NLIMITS) continue;

        rlimit limit;
        limit.rlim_cur = limit.rlim_max = p.second;

        // wish to receive SIGXCPU or SIGXFSZ to know it is TLE or OLE.
        // NOTE: if pid namespace is used (--isolate-process true), pid 1
        // in the new pid ns is immune to signals (including SIGKILL) by
        // default! This means that rlimit won't work for it. Therefore,
        // a dummy init process is created if possible.
        if (resource == RLIMIT_CPU || resource == RLIMIT_FSIZE) ++limit.rlim_max;

        DEBUG_DO {
            char limit_name[18];
            switch (resource) {
#define CONVERT_NAME(x) case x: strncpy(limit_name, # x, sizeof(limit_name)); break;
                CONVERT_NAME(RLIMIT_CPU);
                CONVERT_NAME(RLIMIT_FSIZE);
                CONVERT_NAME(RLIMIT_DATA);
                CONVERT_NAME(RLIMIT_STACK);
                CONVERT_NAME(RLIMIT_CORE);
                CONVERT_NAME(RLIMIT_RSS);
                CONVERT_NAME(RLIMIT_NOFILE);
                CONVERT_NAME(RLIMIT_AS);
                CONVERT_NAME(RLIMIT_NPROC);
                CONVERT_NAME(RLIMIT_MEMLOCK);
                CONVERT_NAME(RLIMIT_LOCKS);
                CONVERT_NAME(RLIMIT_SIGPENDING);
                CONVERT_NAME(RLIMIT_MSGQUEUE);
                CONVERT_NAME(RLIMIT_NICE);
                CONVERT_NAME(RLIMIT_RTPRIO);
                CONVERT_NAME(RLIMIT_RTTIME);
#undef CONVERT_NAME
                default:
                    snprintf(limit_name, sizeof(limit_name), "0x%x", resource);
            }
            rlimit current;
            getrlimit(resource, &current);
            INFO("setrlimit %s, cur: %d => %d, max: %d => %d", limit_name,
                 (int)current.rlim_cur, (int)limit.rlim_cur,
                 (int)current.rlim_max, (int)limit.rlim_max);
        }

        if (setrlimit(resource, &limit)) {
            WARNING("can not set rlimit %d", resource);
        }
    }
}

static void do_set_env(const Cgroup::spawn_arg& arg) {
    // prepare env
    if (arg.reset_env) {
        INFO("reset ENV");
        if (clearenv()) FATAL("can not clear env");
    }

    FOR_EACH(p, arg.env_list) {
        const char * name = p.first.c_str();
        const char * value = p.second.c_str();

        if (setenv(name, value, 1)) FATAL("can not set env %s=%s", name, value);
    }
}

static void do_seccomp(const Cgroup::spawn_arg& arg) {
    // syscall whitelist
    if (seccomp::supported() && arg.syscall_list.length() > 0) {
        // apply seccomp, it will set PR_SET_NO_NEW_PRIVS
        // libseccomp actually has an option to skip setting PR_SET_NO_NEW_PRIVS to 1
        // however it makes seccomp_load error with EPERM because we just used setuid()
        // and PR_SET_SECCOMP needs root if PR_SET_NO_NEW_PRIVS is unset.
        INFO("applying syscall filters");
        seccomp::Rules rules(arg.syscall_action, (uint64_t)(void*)arg.args /* special case for execve arg1 */);

        if (rules.add_simple_filter(arg.syscall_list.c_str())) {
            FATAL("failed to parse syscall filter string");
            exit(-1);
        }
        if (rules.apply()) {
            FATAL("failed to apply seccomp rules");
            exit(-1);
        }
    }
}

static void do_set_new_privs(const Cgroup::spawn_arg& arg) {
    #ifndef PR_SET_NO_NEW_PRIVS
    # define PR_SET_NO_NEW_PRIVS 38
    #endif

    #ifndef PR_GET_NO_NEW_PRIVS
    # define PR_GET_NO_NEW_PRIVS 39
    #endif

    if (arg.no_new_privs) {
        int e = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
        if (e == -1) {
            INFO("NO_NEW_PRIVS is not supported by kernel");
        } else if (e == 0) {
            INFO("prctl PR_SET_NO_NEW_PRIVS");
            int e = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if (e) {
                FATAL("prctl PR_SET_NO_NEW_PRIVS");
                exit(-1);
            }
        }
    }
}

static void init_signal_handler(int signal) {
    if (signal == SIGCHLD) {
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0);
    } else {
        exit(1);
    }
}

static int clone_init_fn(void *) {
    // a dummy init process in new pid namespace
    // intended to be killed via SIGKILL from root pid namespace
    prctl(PR_SET_PDEATHSIG, SIGHUP);

    {
        struct sigaction action;
        action.sa_handler = init_signal_handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        sigaction(SIGKILL, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGPIPE, &action, NULL);
        sigaction(SIGALRM, &action, NULL);
        sigaction(SIGCHLD, &action, NULL);
    }

    // close all fds
    {
        list<int> fds = get_fds();
        INFO("init is running");
        FOR_EACH(fd, fds) close(fd);
    }

    while (1) pause();
    return 0;
}

static int clone_main_fn(void * clone_arg) {
    // kill us if parent dies
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    // this is executed in child process after clone
    // fs and uid settings should be done here
    Cgroup::spawn_arg& arg = *(Cgroup::spawn_arg*)clone_arg;

#ifdef SYSCTL_PER_NS_WORKS
    // NOTE: Do not uncomment this until sysctl per namespace works.
    // current kernel use global variables for vm.oom_kill_allocating_task,
    // etc.
    do_set_sysctl();
#endif
    do_set_uts(arg);
    do_set_netns(arg);
    do_process_fds(arg);
    do_privatize_filesystem(arg);
    do_umount_outside_chroot(arg);
    do_mount_proc(arg);
    do_hide_sensitive(arg);
    do_mount_bindfs(arg);
    do_remounts(arg);
    do_chroot(arg);
    do_mount_tmpfs(arg);
    do_remount_dev(arg);
    do_chdir(arg);
    do_commands(arg);
    do_set_umask(arg);
    do_set_uid_gid(arg);
    do_apply_rlimits(arg);
    do_set_env(arg);
    do_renice(arg);
    do_set_new_privs(arg);

    // all prepared! blocking, wait for parent
    INFO("waiting for parent");
    char buf[4];
    int ret = read(arg.sockets[0], buf, sizeof buf);
    (void)ret;

    // let parent know we got the message, parent then can close fd without SIGPIPE child
    INFO("got from parent: '%3s'. notify parent", buf);
    strncpy(buf, "PRE", sizeof buf);
    ret = write(arg.sockets[0], buf, sizeof buf);
    (void)ret;

    // not closing sockets[0] here, it will closed on exec
    // if exec fails, it will be closed upon process exit (aka. this function returns)
    fd_set_cloexec(arg.sockets[0]);

    // it's time for callback, write log first because fanotify may block us from
    // doing that
    int callback_ret = 0;
    if (arg.callback_child) {
        INFO("will run callback and execvp %s ...", arg.args[0]);
        callback_ret = arg.callback_child((void *) &arg);
    } else {
        INFO("will execvp %s ...", arg.args[0]);
    }

    if (callback_ret == 0) {
        // exec target. syscall filter must be done just before execve because we need other
        // syscalls in above code.
        do_seccomp(arg);
        execvp(arg.args[0], arg.args);
        // if exec fails, write reason down (child knows more details than parent)
        ERROR("exec '%s' failed", arg.args[0]);
    }

    // exec or callback failed
    // notify parent that exec failed
    strncpy(buf, "ERR", sizeof buf);
    ret = write(arg.sockets[0], buf, sizeof buf);
    (void)ret;

    // wait parent
    ret = read(arg.sockets[0], buf, sizeof buf);
    (void)ret;

    return -1;
} // clone_main_fn

static int is_setns_pidns_supported() {
    string pidns_path = string(fs::PROC_PATH) + "/self/ns/pid";
    int fd = open(pidns_path.c_str(), O_RDONLY);
    if (fd == -1) return 0;
    close(fd);
    return 1;
}

#ifndef NDEBUG
static string clone_flags_to_str(int clone_flags) {
    int v = clone_flags;
    string s;
#define TEST_FLAG(x) if ((v & x) != 0) { s += string(# x) + " | "; v ^= x; }
    TEST_FLAG(CLONE_VM);
    TEST_FLAG(CLONE_FS);
    TEST_FLAG(CLONE_FILES);
    TEST_FLAG(CLONE_SIGHAND);
    TEST_FLAG(CLONE_PTRACE);
    TEST_FLAG(CLONE_VFORK);
    TEST_FLAG(CLONE_PARENT);
    TEST_FLAG(CLONE_THREAD);
    TEST_FLAG(CLONE_NEWNS);
    TEST_FLAG(CLONE_SYSVSEM);
    TEST_FLAG(CLONE_SETTLS);
    TEST_FLAG(CLONE_PARENT_SETTID);
    TEST_FLAG(CLONE_CHILD_CLEARTID);
    TEST_FLAG(CLONE_DETACHED);
    TEST_FLAG(CLONE_UNTRACED);
    TEST_FLAG(CLONE_CHILD_SETTID);
    TEST_FLAG(CLONE_NEWUTS);
    TEST_FLAG(CLONE_NEWIPC);
    TEST_FLAG(CLONE_NEWUSER);
    TEST_FLAG(CLONE_NEWPID);
    TEST_FLAG(CLONE_NEWNET);
    TEST_FLAG(CLONE_IO);
    TEST_FLAG(SIGCHLD);

    TEST_FLAG(SIGINT);
    TEST_FLAG(SIGQUIT);
    TEST_FLAG(SIGILL);
    TEST_FLAG(SIGTRAP);
    TEST_FLAG(SIGABRT);
    TEST_FLAG(SIGIOT);
    TEST_FLAG(SIGBUS);
    TEST_FLAG(SIGFPE);
    TEST_FLAG(SIGKILL);
    TEST_FLAG(SIGUSR1);
    TEST_FLAG(SIGSEGV);
    TEST_FLAG(SIGUSR2);
    TEST_FLAG(SIGPIPE);
    TEST_FLAG(SIGALRM);
    TEST_FLAG(SIGTERM);
    TEST_FLAG(SIGSTKFLT);
    TEST_FLAG(SIGCLD);
    TEST_FLAG(SIGCHLD);
    TEST_FLAG(SIGCONT);
    TEST_FLAG(SIGSTOP);
    TEST_FLAG(SIGTSTP);
    TEST_FLAG(SIGTTIN);
    TEST_FLAG(SIGTTOU);
    TEST_FLAG(SIGURG);
    TEST_FLAG(SIGXCPU);
    TEST_FLAG(SIGXFSZ);
    TEST_FLAG(SIGVTALRM);
    TEST_FLAG(SIGPROF);
    TEST_FLAG(SIGWINCH);
    TEST_FLAG(SIGPOLL);
    TEST_FLAG(SIGIO);
    TEST_FLAG(SIGPWR);
    TEST_FLAG(SIGSYS);
#ifdef SIGUNUSED
    TEST_FLAG(SIGUNUSED);
#endif
#undef TEST_FLAG
    if (v) {
        s += strconv::from_long((long)v);
    } else {
        s = s.substr(0, s.length() - 3);
    }
    return s;
}
#endif
