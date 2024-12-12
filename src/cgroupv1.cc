////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017-2024 Shaolei Zhou <zhoushaolei@pat-edu.com>
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "cgroup.h"
#include "utils/linux_only.h"
#include "utils/for_each.h"
#include "utils/fs.h"
#include "utils/strconv.h"

using namespace lrun;

using std::string;
using std::list;

const char CgroupV1::subsys_names[4][8] = {
        "cpuacct",
        "memory",
        "devices",
        "freezer",
};

std::string CgroupV1::subsys_base_paths_[sizeof(subsys_names) / sizeof(subsys_names[0])];

int CgroupV1::subsys_id_from_name(const char * const name) {
    for (size_t i = 0; i < sizeof(CgroupV1::subsys_names) / sizeof(CgroupV1::subsys_names[0]); ++i) {
        if (strcmp(name, subsys_names[i]) == 0) return i;
    }
    return -1;
}

string CgroupV1::base_path(subsys_id_t subsys_id, bool create_on_need) {
    {
        // FIXME cache may not work when user manually umount cgroup
        // check last cached path
        const string& path = subsys_base_paths_[subsys_id];
        if ((!path.empty()) && fs::is_dir(path)) return path;
    }

    const char * const MNT_SRC_NAME = "cgroup_lrun";
    const char * MNT_DEST_BASE_PATH = "/sys/fs/cgroup";
    const char * subsys_name = subsys_names[subsys_id];

    std::map<string, fs::MountEntry> mounts = fs::get_mounts();
    FOR_EACH_CONST(p, mounts) {
        const fs::MountEntry& ent = p.second;
        if (ent.type != string(fs::TYPE_CGROUP)) continue;
        if (strstr(ent.opts.c_str(), subsys_name)) {
            INFO("cgroup %s path = '%s'", subsys_name, ent.dir.c_str());
            return (subsys_base_paths_[subsys_id] = string(ent.dir));
        }
    }

    // no cgroups mounted, prepare one
    if (!create_on_need) return "";

    if (!fs::is_dir(MNT_DEST_BASE_PATH)) {
        // no /sys/fs/cgroup in system, try conservative location
        MNT_DEST_BASE_PATH = "/cgroup";
        mkdir(MNT_DEST_BASE_PATH, 0700);
    }

    // prepare tmpfs on MNT_DEST_BASE_PATH
    int dest_base_mounted = 0;

    if (mounts.count(string(MNT_DEST_BASE_PATH)) == 0) {
        int e = mount(NULL, MNT_DEST_BASE_PATH, fs::TYPE_TMPFS, MS_NOEXEC | MS_NOSUID, "size=16384,mode=0755");
        if (e != 0) FATAL("can not mount tmpfs on '%s'", MNT_DEST_BASE_PATH);
        dest_base_mounted = 1;
    } else {
        INFO("'%s' is already mounted, skip mounting tmpfs", MNT_DEST_BASE_PATH);
    }

    // create and mount cgroup at dest_path
    string dest_path = string(MNT_DEST_BASE_PATH) + "/" + subsys_name;
    INFO("mkdir and mounting '%s'", dest_path.c_str());
    mkdir(dest_path.c_str(), 0700);
    int e = mount(MNT_SRC_NAME, dest_path.c_str(), fs::TYPE_CGROUP, MS_NOEXEC | MS_NOSUID | MS_RELATIME | MS_NODEV, subsys_name);

    if (e != 0) {
        int last_err = errno;
        // fallback, umount tmpfs if it is just mounted
        if (dest_base_mounted) umount(MNT_DEST_BASE_PATH);
        errno = last_err;
        FATAL("can not mount cgroup %s on '%s'", subsys_name, dest_path.c_str());
    }

    return (subsys_base_paths_[subsys_id] = dest_path);
}

string CgroupV1::path_from_name(subsys_id_t subsys_id, const string& name) {
    return base_path(subsys_id) + "/" + name;
}

string CgroupV1::subsys_path(CgroupV1::subsys_id_t subsys_id) const {
    return path_from_name(subsys_id, name_);
}

string CgroupV1::lock_path() const {
    return subsys_path();
}

int CgroupV1::exists(const string& name) {
    for (int id = 0; id < SUBSYS_COUNT; ++id) {
        if (!fs::is_dir(path_from_name((subsys_id_t)(id), name))) return false;
    }
    return true;
}


CgroupV1 CgroupV1::create(const string& name) {
    CgroupV1 cg;

    if (exists(name)) {
        INFO("create cgroup '%s': already exists", name.c_str());
        cg.name_ = name;
        return cg;
    }
    int success = 1;
    for (int id = 0; id < SUBSYS_COUNT; ++id) {
        string path = path_from_name((subsys_id_t)id, name);
        if (fs::is_dir(path)) continue;
        if (mkdir(path.c_str(), 0700)) {
            ERROR("mkdir '%s': failed", path.c_str());
            success = 0;
            break;
        }
    }
    if (success) cg.name_ = name;
    cg.init_pid_ = 0;

    return cg;
}

CgroupV1::CgroupV1() { version_ = 1; }

bool CgroupV1::valid() const {
    return !name_.empty() && exists(name_);
}

void CgroupV1::update_output_count() {
    if (!valid()) return;
    string procs_path = subsys_path(CG_FREEZER) + "/cgroup.procs";
    if (fs::read(procs_path, 4).empty()) return;

    FILE * procs = fopen(procs_path.c_str(), "r");
    char spid[26]; // sizeof(pid_t) * 3 + 2, assuming sizeof(pid_t) is 8
    while (fscanf(procs, "%25s", spid) == 1) {
        unsigned long pid;
        unsigned long long bytes = 0;
        if (sscanf(spid, "%lu", &pid) == 0) continue;
        FILE * io = fopen((string(fs::PROC_PATH) + "/" + spid + "/io").c_str(), "r");
        if (!io) continue;
        int res = 0;
        res = fscanf(io, "rchar: %*s\nwchar: %Lu", &bytes);
        if (res == 1) {
            if (output_counter_[pid] < bytes) output_counter_[pid] = bytes;
        }
        fclose(io);
    }
    fclose(procs);
}

long long CgroupV1::output_usage() const {
    long long bytes = 0;
    FOR_EACH_CONST(p, output_counter_) {
        bytes += p.second;
    }
    return bytes;
}

list<pid_t> CgroupV1::get_pids() {
    string procs_path = subsys_path(CG_FREEZER) + "/cgroup.procs";
    FILE * procs = fopen(procs_path.c_str(), "r");
    list<pid_t> pids;

    if (procs) {
        unsigned long pid;
        while (fscanf(procs, "%lu", &pid) == 1) pids.push_back((pid_t)pid);
        fclose(procs);
    }
    return pids;
}

bool CgroupV1::has_pid(pid_t pid) {
    bool result = false;

    char path[sizeof(long) * 3 + sizeof("/proc//cgroup")];
    snprintf(path, sizeof(path), "/proc/%ld/cgroup", (long)pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return false;

    size_t len = 0;
    char *line = NULL;
    char buf[64];  // FIXME cgroup name is 63 chars long
    while (getline(&line, &len, fp) != -1) {
        // the line should look like:
        // 4:memory:/cgname
        if (sscanf(line, "%*d:memory:/%63s", buf) != 1)
            continue;
        result = (strncmp(name_.c_str(), buf, sizeof(buf)) == 0);
        break;
    }
    if (line) free(line);
    fclose(fp);
    return result;
}

static const useconds_t LOOP_ITERATION_INTERVAL = 10000;  // 10 ms

int CgroupV1::freeze(bool freeze, int timeout) {
    if (!valid()) return -1;
    string freeze_state_path = subsys_path(CG_FREEZER) + "/freezer.state";

    if (!freeze) {
        INFO("unfreeze");
        fs::write(freeze_state_path, "THAWED\n");
    } else {
        INFO("freezing");
        fs::write(freeze_state_path, "FROZEN\n");

        for (;;) {
            int frozen = (strncmp(fs::read(freeze_state_path, 4).c_str(), "FRO", 3) == 0);
            if (frozen) break;

            timeout--;
            if (timeout == 1) {
                INFO("enabling OOM killer");
                set(CG_MEMORY, "memory.oom_control", "0\n");
            } else if (timeout <= 0) {
                INFO("giving up, not frozen");
                return -2;
            }

            usleep(LOOP_ITERATION_INTERVAL);
        }
        INFO("confirmed frozen");
    }
    return 0;
}

int CgroupV1::empty() {
    string procs_path = subsys_path(CG_FREEZER) + "/cgroup.procs";
    return fs::read(procs_path, 4).empty() ? 1 : 0;
}

void CgroupV1::killall(bool confirm) {
    // The init pid can be outside the cgroup task list. Therefore do not
    // test "empty()" here.
    if (!valid()) return;

    if (init_pid_) {
        if (init_pid_ > 0) {
            // if init pid exists, just kill it and the kernel will kill all
            // remaining processes in the same pid ns.
            // because our init process (clone_init_fn) won't allocate memory,
            // it will not enter D state and is safe to kill.
            kill(init_pid_, SIGKILL);
            // cancel memory limit. this will wake up some D state processes,
            // which are allocating memory and reached memory limit.
            set_memory_limit(-1);
            INFO("sent SIGKILL to init process %lu", (unsigned long)init_pid_);
            init_pid_ = -1;
        }

        if (confirm) {
            // wait and confirm that processes are gone
            for (int clear = 0; clear == 0;) {
                if (!valid() || empty()) break;
                usleep(LOOP_ITERATION_INTERVAL);
            }
        }
    } else {
        // legacy (unreliable) way to kill processes, or not using a pid
        // namespace
        while (valid() && !empty()) {
            freeze(true, 2);
            list<pid_t> pids = get_pids();
            FOR_EACH(p, pids) kill(p, SIGKILL);
            INFO("sent SIGKILLs to %lu processes", (unsigned long)pids.size());
            if (!confirm) break;
            freeze(false, 1);
            if (!empty()) usleep(LOOP_ITERATION_INTERVAL);
        }
    }

    return;
}

int CgroupV1::destroy() {
    killall();

    int ret = 0;
    for (int id = 0; id < SUBSYS_COUNT; ++id) {
        string path = subsys_path((subsys_id_t)id);
        if (path.empty()) continue;
        if (fs::is_dir(path)) ret |= rmdir(path.c_str());
    }

    return ret;
}

int CgroupV1::set(subsys_id_t subsys_id, const string& property, const string& value) {
    INFO("set cgroup %s/%s to %s", subsys_path(subsys_id).c_str(), property.c_str(), value.c_str());
    return fs::write(subsys_path(subsys_id) + "/" + property, value);
}

string CgroupV1::get(subsys_id_t subsys_id, const string& property, size_t max_length) const {
    return fs::read(subsys_path(subsys_id) + "/" + property, max_length);
}

int CgroupV1::inherit(subsys_id_t subsys_id, const string& property) {
    string value = fs::read(base_path(subsys_id, false) + "/" + property);
    return fs::write(subsys_path(subsys_id) + "/" + property, value);
}

int CgroupV1::configure(std::map<std::pair<CgroupV1::subsys_id_t, std::string>, std::string> cgroup_options) {
    // some cgroup options, fail quietly
    set(CgroupV1::CG_MEMORY, "memory.swappiness", "0\n");

    // enable oom killer now so our buggy code won't freeze.
    // we will disable it later.
    set(CgroupV1::CG_MEMORY, "memory.oom_control", "0\n");

    // other cgroup options
    FOR_EACH(p, cgroup_options) {
        if (set(p.first.first, p.first.second, p.second)) {
            ERROR("can not set cgroup option '%s' to '%s'", p.first.second.c_str(), p.second.c_str());
            return -1;
        }
    }
    return 0;
}


int CgroupV1::attach(pid_t pid) {
    char pidbuf[32];
    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long)pid);

    int ret = 0;
    for (int id = 0; id < SUBSYS_COUNT; ++id) {
        string path = subsys_path((subsys_id_t)id);
        // FIXME: It seems pid should be write into /cgroup.procs and tid should be write into /tasks
        ret |= fs::write(path + "/cgroup.procs", pidbuf);
    }

    return ret;
}

int CgroupV1::limit_devices() {
    int e = 0;
    e += set(CG_DEVICES, "devices.deny", "a");
    for (size_t i = 0; i < sizeof(basic_devices) / sizeof(basic_devices[0]); ++i) {
        long minor = basic_devices[i].minor;
        string v = string("c 1:" + strconv::from_long(minor) + " rwm");
        e += set(CG_DEVICES, "devices.allow", v);
    }
    return e ? -1 : 0;
}

int CgroupV1::reset_usages() {
    int e = 0;
    e += set(CG_CPUACCT, "cpuacct.usage", "0");
    e += set(CG_MEMORY, "memory.max_usage_in_bytes", "0") * set(CG_MEMORY, "memory.memsw.max_usage_in_bytes", "0");
    output_counter_.clear();
    return e ? -1 : 0;
}

int CgroupV1::reset_cpu_usage() {
    int e = 0;
    e = set(CG_CPUACCT, "cpuacct.usage", "0");
    return e ? -1 : 0;
}

double CgroupV1::cpu_usage() const {
    string cpu_usage = get(CG_CPUACCT, "cpuacct.usage", 31);
    // convert from nanoseconds to seconds
    return strconv::to_double(cpu_usage) / 1e9;
}

long long CgroupV1::memory_current() const {
    string usage = get(CG_MEMORY, "memory.memsw.usage_in_bytes");
    if (usage.empty()) usage = get(CG_MEMORY, "memory.usage_in_bytes");
    return strconv::to_longlong(usage);
}

long long CgroupV1::memory_peak() const {
    string usage = get(CG_MEMORY, "memory.memsw.max_usage_in_bytes");
    if (usage.empty()) usage = get(CG_MEMORY, "memory.max_usage_in_bytes");
    return strconv::to_longlong(usage);
}

long long CgroupV1::memory_limit() const {
    string limit = get(CG_MEMORY, "memory.memsw.limit_in_bytes");
    if (limit.empty()) limit = get(CG_MEMORY, "memory.limit_in_bytes");
    return strconv::to_longlong(limit);
}

bool CgroupV1::is_under_oom() const {
    string content = get(CG_MEMORY, "memory.oom_control");
    return content.find("under_oom 1") != string::npos;
}

long long CgroupV1::set_memory_limit(long long bytes) {
    int e = 1;

    if (bytes <= 0) {
        // read base (parent) cgroup properties
        e *= inherit(CG_MEMORY, "memory.limit_in_bytes");
        e *= inherit(CG_MEMORY, "memory.memsw.limit_in_bytes");
    } else {
        e *= set(CG_MEMORY, "memory.limit_in_bytes", strconv::from_longlong(bytes));
        e *= set(CG_MEMORY, "memory.memsw.limit_in_bytes", strconv::from_longlong(bytes));
    }

    if (e) {
        return -1;
    } else {
        // The kernel might "adjust" the memory limit. Read it back.
        string limit = get(CG_MEMORY, "memory.memsw.limit_in_bytes");
        return strconv::to_longlong(limit);
    }
}

pid_t CgroupV1::spawn(spawn_arg& arg) {
    // uid and gid should > 0
    if (arg.uid <= 0 || arg.gid <= 0) {
        WARNING("uid and gid can not <= 0. spawn rejected");
        return -2;
    }

    // stack size for cloned processes
    long stack_size = sysconf(_SC_PAGESIZE);
    static const long MIN_STACK_SIZE = 8192;
    if (stack_size < MIN_STACK_SIZE) stack_size = MIN_STACK_SIZE;

    // We need root permissions and drop root later, no CLONE_NEWUSER here
    // CLONE_NEWNS is required for private mounts
    // CLONE_NEWUSER is not used because new uid 0 may be non-root
    int clone_flags = CLONE_NEWNS | SIGCHLD | arg.clone_flags;

    // older kernel (ex. Debian 7, 3.2.0) doesn't support setns(whatever, CLONE_PIDNS)
    // just do not create init process in that case.
    if (is_setns_pidns_supported() && (clone_flags & CLONE_NEWPID) == CLONE_NEWPID) {
        // create a dummy init process in a new namespace
        // CLONE_PTRACE: prevent the process being traced by another process
        INFO("spawning dummy init process");
        int init_clone_flags = CLONE_NEWPID;
        init_pid_ = clone(clone_init_fn, (void*)((char*)alloca(stack_size) + stack_size), init_clone_flags, &arg);
        if (init_pid_ < 0) {
            ERROR("can not spawn init process");
            return -3;
        }

        // switch to that pid namespace for our next clone
        string pidns_path = string(fs::PROC_PATH) + "/" + strconv::from_ulong((unsigned long)init_pid_) + "/ns/pid";
        INFO("set pid ns to %s", pidns_path.c_str());
        int pidns_fd = open(pidns_path.c_str(), O_RDONLY);
        if (pidns_fd < 0) {
            ERROR("can not open pid namespace");
            return -3;
        }

        // older glibc does not have setns
        if (syscall(SYS_setns, pidns_fd, CLONE_NEWPID)) {
            ERROR("can not set pid namespace");
            return -3;
        };
        close(pidns_fd);

        // remove CLONE_NEWPID flag because setns() will affect all new processes
        clone_flags ^= CLONE_NEWPID;
    } // spawn init process

    DEBUG_DO {
        INFO("clone flags = 0x%x = %s", (int)clone_flags, clone_flags_to_str(clone_flags).c_str());
    }

    // do sync use socket pair
    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, arg.sockets)) {
        ERROR("socketpair failed");
        return -1;
    }

    // sockets fds should expire when exec
    fd_set_cloexec(arg.sockets[0]);
    fd_set_cloexec(arg.sockets[1]);

    pid_t child_pid;
    child_pid = clone(clone_main_fn, (void*)((char*)alloca(stack_size) + stack_size), clone_flags, &arg);
    char buf[4];
    ssize_t ret;

    if (child_pid < 0) {
        FATAL("clone failed");
        goto cleanup;
    }

    INFO("child pid = %lu", (unsigned long)child_pid);

    // attach child to current cgroup. cpu and memory
    // resource counter start to work from here
    INFO("attach %lu", (unsigned long)child_pid);
    attach(child_pid);

    // child is blocking, waiting us before exec
    // it's time to let the child go
    strncpy(buf, "RUN", sizeof buf);
    close(arg.sockets[0]);
    ret = send(arg.sockets[1], buf, sizeof buf, MSG_NOSIGNAL);
    if (ret < 0) {
        WARNING("can not send let-go message to child");
        goto cleanup;
    }

    // wait for child response
    INFO("reading from child");

    buf[0] = 0;
    ret = read(arg.sockets[1], buf, sizeof buf);

    INFO("from child, got '%3s'", buf);
    if (buf[0] != 'P' || ret <= 0) {  // excepting "PRE"
        // child has problem to start
        child_pid = -3;
        goto cleanup;
    }

    // child exec may fail, confirm
    if (read(arg.sockets[1], buf, sizeof buf) > 0 && buf[0] == 'E') {  // "ERR"
        INFO("seems child exec failed");
        child_pid = -4;
        goto cleanup;
    }

    // the child has exec successfully
    // disable oom killer because it will make dmesg noisy.
    // Note: a process can enter D (uninterruptable sleep) status
    // when oom killer disabled, killing it requires re-enable oom killer
    // or enlarge memory limit
    INFO("disabling oom killer");
    if (set(CG_MEMORY, "memory.oom_control", "1\n")) INFO("can not set memory.oom_control");

    cleanup:
    close(arg.sockets[1]);
    return child_pid;
}
