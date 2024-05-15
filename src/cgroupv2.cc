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
#include <climits>
#include "cgroup.h"
#include "cgroup.cc"
#include "utils/linux_only.h"
#include "utils/for_each.h"
#include "utils/fs.h"
#include "utils/strconv.h"

using namespace lrun;

using std::string;
using std::list;

string CgroupV2::base_path(bool create_on_need) {
    const char * const MNT_SRC_NAME = "cgroup_lrun";
    const char * MNT_DEST_BASE_PATH = "/sys/fs/cgroup";

    std::map<string, fs::MountEntry> mounts = fs::get_mounts();
    FOR_EACH_CONST(p, mounts) {
        const fs::MountEntry& ent = p.second;
        if (ent.type != string(fs::TYPE_CGROUP2)) continue;
        return ent.dir;
    }

    // no cgroups mounted, prepare one
    if (!create_on_need) return "";

    if (!fs::is_dir(MNT_DEST_BASE_PATH)) {
        // no /sys/fs/cgroup in system, try conservative location
        MNT_DEST_BASE_PATH = "/cgroup";
        mkdir(MNT_DEST_BASE_PATH, 0700);
    }

    // create and mount cgroup at dest_path
    string dest_path = string(MNT_DEST_BASE_PATH);
    INFO("mkdir and mounting '%s'", dest_path.c_str());
    mkdir(dest_path.c_str(), 0700);
    /**
     * TODO: there should be additional flag: nsdelegate,memory_recursiveprot?
     */
    int e = mount(MNT_SRC_NAME, dest_path.c_str(), fs::TYPE_CGROUP2, MS_NOEXEC | MS_NOSUID | MS_RELATIME | MS_NODEV, "nsdelegate,memory_recursiveprot");

    if (e != 0) {
        FATAL("can not mount cgroup v2 '%s'", dest_path.c_str());
    }
    return dest_path;
}

string CgroupV2::path_from_name(const string& name) {
    return base_path() + "/" + name;
}

string CgroupV2::group_path() const {
    return path_from_name(name_);
}

string CgroupV2::lock_path() const {
    return group_path();
}

int CgroupV2::exists(const string& name) {
    if (!fs::is_dir(path_from_name(name))) return false;
    return true;
}

CgroupV2 CgroupV2::create(const string& name) {
    CgroupV2 cg;

    if (exists(name)) {
        INFO("create cgroup '%s': already exists", name.c_str());
        cg.name_ = name;
        return cg;
    }
    int success = 1;
    string path = path_from_name(name);
    if (mkdir(path.c_str(), 0700)) {
        ERROR("mkdir '%s': failed", path.c_str());
        success = 0;
    }
    if (success) cg.name_ = name;
    cg.init_pid_ = 0;

    return cg;
}

CgroupV2::CgroupV2() { version_ = 2; };

bool CgroupV2::valid() const {
    return !name_.empty() && exists(name_);
}

void CgroupV2::update_output_count() {
    if (!valid()) return;
    string procs_path = group_path() + "/cgroup.procs";
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

long long CgroupV2::output_usage() const {
    long long bytes = 0;
    FOR_EACH_CONST(p, output_counter_) {
        bytes += p.second;
    }
    return bytes;
}

list<pid_t> CgroupV2::get_pids() {
    string procs_path = group_path() + "/cgroup.procs";
    FILE * procs = fopen(procs_path.c_str(), "r");
    list<pid_t> pids;

    if (procs) {
        unsigned long pid;
        while (fscanf(procs, "%lu", &pid) == 1) pids.push_back((pid_t)pid);
        fclose(procs);
    }
    return pids;
}

bool CgroupV2::has_pid(pid_t pid) {
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
        // 0::/cgname
        if (sscanf(line, "%*d::/%63s", buf) != 1)
            continue;
        result = (strncmp(name_.c_str(), buf, sizeof(buf)) == 0);
        break;
    }
    if (line) free(line);
    fclose(fp);
    return result;
}

static const useconds_t LOOP_ITERATION_INTERVAL = 10000;  // 10 ms

int CgroupV2::freeze(bool freeze, int timeout) {
    if (!valid()) return -1;
    string freeze_state_path = group_path() + "/cgroup.freeze";

    if (!freeze) {
        INFO("unfreeze");
        fs::write(freeze_state_path, "0\n");
    } else {
        INFO("freezing");
        fs::write(freeze_state_path, "1\n");

        for (;;) {
            int frozen = (strncmp(fs::read(freeze_state_path, 4).c_str(), "1", 3) == 0);
            if (frozen) break;

            timeout--;
            if (timeout <= 0) {
                INFO("giving up, not frozen");
                return -2;
            }

            usleep(LOOP_ITERATION_INTERVAL);
        }
        INFO("confirmed frozen");
    }
    return 0;
}

int CgroupV2::empty() {
    string procs_path = group_path() + "/cgroup.procs";
    return fs::read(procs_path, 4).empty() ? 1 : 0;
}

void CgroupV2::killall(bool confirm) {
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

int CgroupV2::destroy() {
    killall();

    int ret = 0;
    if (fs::is_dir(group_path())) ret |= rmdir(group_path().c_str());

    return ret;
}

int CgroupV2::set(const string& property, const string& value) {
    INFO("set cgroup %s to %s", property.c_str(), value.c_str());
    return fs::write(group_path() + "/" + property, value);
}

string CgroupV2::get(const string& property, size_t max_length) const {
    return fs::read(group_path() + "/" + property, max_length);
}

int CgroupV2::inherit(const string& property) {
    string value = fs::read(base_path(false) + "/" + property);
    return fs::write(group_path() + "/" + property, value);
}

int CgroupV2::configure(std::map<std::string, std::string> cgroup_options) {
    // some cgroup options, fail quietly
    set("memory.swap.max", "0\n");

    // other cgroup options
    FOR_EACH(p, cgroup_options) {
        if (set(p.first, p.second)) {
            ERROR("can not set cgroup option '%s' to '%s'", p.first.c_str(), p.second.c_str());
            return -1;
        }
    }
    return 0;
}

int CgroupV2::attach(pid_t pid) {
    char pidbuf[32];
    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long)pid);

    int ret = 0;
    ret |= fs::write(group_path() + "/cgroup.procs", pidbuf);

    return ret;
}

int CgroupV2::limit_devices() {
    int e = 0;
    /** cgroup v2 not support limit devices by default:
     *      Cgroup v2 device controller has no interface files and is implemented
     *      on top of cgroup BPF. To control access to device files, a user may
     *      create bpf programs of the BPF_CGROUP_DEVICE type and attach them
     */
    return e ? -1 : 0;
}

int CgroupV2::reset_usages() {
    int e = 0;
    /**
     * cgroup v2 not support reset status, so we check the current status.
     * if it is not clear, return error.
     */
    e += cpu_usage() != 0.0;
    e += memory_peak() != 0;
    output_counter_.clear();
    return e ? -1 : 0;
}

int CgroupV2::reset_cpu_usage() {
    int e = 0;
    /**
     * cgroup v2 seems not support reset status
     */
    return e ? -1 : 0;
}

double CgroupV2::cpu_usage() const {
    char cpu_usage[32];
    string content = get("cpu.stat", 32);
    if (sscanf(content.c_str(), "usage_usec %31s", cpu_usage) == 0) {
        return 0.0;
    }
    // convert from useconds(microseconds) to seconds
    return strconv::to_double(cpu_usage) / 1e6;
}

long long CgroupV2::memory_current() const {
    string usage = get("memory.current");
    /**
     * in cgroup v2, there is no memory.swap.peak.
     * so we do not count swap usage currently.
     */
    // string swap_usage = get("memory.swap.current");
    // return strconv::to_longlong(usage) + strconv::to_longlong(swap_usage);
    return strconv::to_longlong(usage);
}

long long CgroupV2::memory_peak() const {
    /**
     * in cgroup v2, there is no memory.swap.peak.
     * so we do not count swap usage currently.
     */
    string usage = get("memory.peak");
    return strconv::to_longlong(usage);
}

long long CgroupV2::memory_limit() const {
    string limit = get("memory.max");
    if (strcmp(limit.c_str(), "max") == 0) return LLONG_MAX;
    return strconv::to_longlong(limit);
}

bool CgroupV2::is_under_oom() const {
    string content = get("memory.events");
    string sub_content = content.substr(content.find("oom "));
    int count;
    if (sscanf(sub_content.c_str(), "oom %d", &count) == 0) return false;
    return count > 0;
}

long long CgroupV2::set_memory_limit(long long bytes) {
    int e = 1;

    if (bytes <= 0) {
        // read base (parent) cgroup properties
        e *= inherit("memory.max");
    } else {
        e *= set("memory.max", strconv::from_longlong(bytes));
    }

    if (e) {
        return -1;
    } else {
        // The kernel might "adjust" the memory limit. Read it back.
        string limit = get("memory.max");
        return strconv::to_longlong(limit);
    }
}

pid_t CgroupV2::spawn(spawn_arg& arg) {
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

    /**
     * oom killer disable is not available for cgroup v2.
     */

    cleanup:
    close(arg.sockets[1]);
    return child_pid;
}
