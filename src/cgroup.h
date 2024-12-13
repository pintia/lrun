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

#pragma once

#ifndef TESTTEST
#define TESTTEST

#include <string>
#include <map>
#include <set>
#include <list>
#include <sys/resource.h>
#include <memory>
#include "seccomp.h"

// Old system does not have RLIMIT_RTTIME, define it as invalid
#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME RLIMIT_NLIMITS
#endif

namespace lrun {
    class Cgroup;

    typedef int cgroup_callback_func(void *);

    class Cgroup {
    public:
        /**
         * create a cgroup, use existing if possible
         * @return  Cgroup object
         */
        // virtual Cgroup create(const std::string &name) = 0;

        /**
         * file path for lock
         * @return lock path
         */
        virtual std::string lock_path() const = 0;

        /**
         * cgroup version
         * @return 1            v1
         *         2            v2
         */
        int version() { return version_; };

        /**
         * kill all processes and destroy this cgroup
         * @return 0            success
         *         other        failed
         */
        virtual int destroy() = 0;

        /**
         * set a cgroup property
         * WARNING: property is not filtered, do not pass untrusted user-generated
         * content here!
         *
         * @param   property    property
         * @param   value       value
         * @return  0           success
         *         <0           failed
         */
         // abstract int set();

        /**
         * get property
         * @param   property    property
         * @param   max_length  max length to read (not include '\0')
         * @return  string      readed property, empty if fail
         */
         // abstract std::string get();

        /**
         * set a cgroup property to the same value as parent
         * @param   property    property
         * @return  0           success
         *         <0           failed
         */
         // abstract int inherit();

        /**
         * attach a process
         * @param   pid         process id to attach
         * @return  0           success
         *         <0           failed
         */
        virtual int attach(pid_t pid) = 0;

        /**
         * check if Cgroup is invalid
         * @return  true        valid
         *          false       invalid
         */
        virtual bool valid() const = 0;


        /**
         * scan group processes and update output usage
         */
        virtual void update_output_count() = 0;

        /**
         * return output usage
         * @return  bytes      output usage
         */
        virtual long long output_usage() const = 0;

        /**
         * get pid list
         * @return  pids       a list of pids in the cgroup
         */
        virtual std::list<pid_t> get_pids() = 0;

        // Cgroup high level methods

        /**
         * test if the cgroup has zero processes attached
         * @return  1           yes, the cgroup has no processes attached
         *          0           no, the cgroup has processes attached
         */
        virtual int empty() = 0;

        /**
         * check if a process is in this cgroup
         * @return  true        the process is in this cgroup
         *          false       otherwise
         */
        virtual bool has_pid(pid_t pid) = 0;

        /**
         * kill all tasks until no more tasks alive.
         *
         * @param   confirm     true: block until all tasks are confirmed gone
         *                      false: just send kill, do not confirm
         */
        virtual void killall(bool confirm = true) = 0;

        /**
         * use freezer cgroup subsystem to freeze processes
         * if freeze is non-zero, the method will block until
         * all processes are frozen.
         * freezer may attempt increase memory limit and
         * enable oom to get rid of D state processes.
         *
         * @param   freeze      false: unfreeze. true: freeze
         * @param   timeout     how many iterations before giving up
         * @return  0           success
         *          otherwise   failed
         */
        virtual int freeze(bool freeze = true, int timeout = 5) = 0;

        /**
         * get current memory usage
         * @return  memory usage in bytes
         */
        virtual long long memory_current() const = 0;

        /**
         * get peak memory usage
         * @return  memory usage in bytes
         */
        virtual long long memory_peak() const = 0;

        /**
         * get memory limit
         * @return  memory limit in bytes
         */
        virtual long long memory_limit() const = 0;

        /**
         * test if the cgroup is under OOM
         * @return  true   if under OOM
         *          false  otherwise
         */
        virtual bool is_under_oom() const = 0;

        /**
         * get cpu usage
         * @return  cpu usage in seconds
         */
        virtual double cpu_usage() const = 0;

        /**
         * set memory usage limit
         * @param   bytes       limit, no limit if bytes <= 0
         * @return >=0          success, real memory limit
         *         <0           failed
         */
        virtual long long set_memory_limit(long long bytes) = 0;

        /**
         * restart cpuacct and memory max_usage_in_bytes
         * @return  0           success
         *         <0           failed
         */
        virtual int reset_usages() = 0;

        /**
         * restart cpuacct usage
         * @return  0           success
         *         <0           failed
         */
        virtual int reset_cpu_usage() = 0;

        /**
         * limit devices to null, zero, full, random and urandom
         *
         * @return  0           success
         *         <0           failed
         */
        virtual int limit_devices() = 0;

        /**
         * structure used for forked child
         */
        struct spawn_arg {
            int clone_flags;            // additional clone flags
            char *const *args;        // exec args
            int argc;                   // exec argc
            uid_t uid;                  // uid (should not be 0)
            gid_t gid;                  // gid (should not be 0)
            mode_t umask;               // umask
            int nice;                   // nice
            bool no_new_privs;          // prctl PR_SET_NO_NEW_PRIVS
            bool umount_outside;        // umount things outside chroot
            int sockets[2];             // for sync between child and parent
            std::string chroot_path;    // chroot path, empty if not need to chroot
            std::string chdir_path;     // chdir path, empty if not need to chdir
            std::string syscall_list;   // syscall whitelist or blacklist
            int stdout_fd;              // redirect stdout to
            int stderr_fd;              // redirect stderr to
            int netns_fd;               // netns fd
            struct {                    // set uts namespace strings
                std::string sysname;
                std::string nodename;
                std::string release;
                std::string version;
                std::string domainname;
            } uts;
            seccomp::action_t syscall_action;
            // syscall default action
            std::list<std::pair<std::string, long long> > tmpfs_list;
            // [(dest, bytes)] mount tmpfs in child FS (after chroot)
            std::list<std::pair<std::string, std::string> > bindfs_list;
            std::set<std::string> bindfs_dest_set;
            // [(dest, src)] mount bind in child FS (before chroot)
            // bindfs_dests is for quickly lookup purpose
            std::map<std::string, unsigned long> remount_list;
            // [(dest, flags)] remount list (before chroot)
            std::list<std::string> cmd_list;
            // cp file list
            std::set<int> keep_fds;     // Do not close these fd
            std::map<int, rlim_t> rlimits;
            // [resource, value] rlimit list
            int reset_env;              // Do not inherit env
            int remount_dev;            // Recreate a minimal dev
            std::list<std::pair<std::string, std::string> > env_list;
            // environment variables whitelist
            cgroup_callback_func *callback_child;
            // callback function, just *before* seccomp and execve.
            // run in the context of child process
        };

        /**
         * spawn child process and exec inside cgroup
         * child process is in other namespace in FS, PID, UTS, IPC, NET
         * child process is attached to cgroup just before exec
         * @param   arg         swapn arg, @see struct spawn_arg
         * @return  pid         child pid, negative if failed
         */
        virtual pid_t spawn(spawn_arg &arg) = 0;

    protected:
        /**
         * cgroup version (1 or 2)
         */
        int version_;
        /**
         * cgroup directory name
         */
        std::string name_;

        /**
         * count output bytes
         */
        std::map<unsigned long, unsigned long long> output_counter_;

        /**
         * cached init pid (only valid if pid namespace is enabled)
         */
        pid_t init_pid_;

        Cgroup() {};
    };
}

namespace lrun {
    class CgroupV1;
    class CgroupV2;

    class CgroupV1: public lrun::Cgroup {
    public:
        /**
         * cgroup subsystem ids
         */
        enum subsys_id_t {
            CG_CPUACCT = 0,
            CG_MEMORY  = 1,
            CG_DEVICES = 2,
            CG_FREEZER = 3,
        };

        /**
         * cgroup subsystem names
         */
        static const char subsys_names[4][8];
        static const int SUBSYS_COUNT = sizeof(subsys_names) / sizeof(subsys_names[0]);

        /**
         * get cgroup subsystem id from name
         * @param   name            cgroup subsystem name
         * @return  >=0             cgroup subsystem id
         *          -1              subsystem id not found
         */
        static int subsys_id_from_name(const char * const name);

        /**
         * get cgroup mounted path
         * @param   create_on_need  mount cgroup if not mounted
         * @return  cgroup mounted path (first one in mount table)
         */
        static std::string base_path(subsys_id_t subsys_id, bool create_on_need = true);

        /**
         * create a cgroup, use existing if possible
         * @return  Cgroup object
         */
        static CgroupV1 create(const std::string& name);

        /**
         * set a cgroup property
         * WARNING: property is not filtered, do not pass untrusted user-generated
         * content here!
         *
         * @param   property    property
         * @param   value       value
         * @return  0           success
         *         <0           failed
         */
        int set(subsys_id_t subsys_id, const std::string &property, const std::string &value);

        /**
         * get property
         * @param   property    property
         * @param   max_length  max length to read (not include '\0')
         * @return  string      readed property, empty if fail
         */
        std::string get(subsys_id_t subsys_id, const std::string &property, size_t max_length = 255) const;

        /**
         * configure a cgroup with multiple options
         * generally for initialization
         */
        int configure(std::map<std::pair<CgroupV1::subsys_id_t, std::string>, std::string> cgroup_options);

    protected:
        std::string lock_path() const override;
        bool valid() const override;
        void update_output_count() override;
        long long output_usage() const override;
        std::list<pid_t> get_pids() override;
        bool has_pid(pid_t pid) override;
        int freeze(bool freeze = true, int timeout = 5) override;
        int empty() override;
        void killall(bool confirm = true) override;
        int destroy() override;
        int attach(pid_t pid) override;
        int limit_devices() override;
        int reset_usages() override;
        int reset_cpu_usage() override;
        double cpu_usage() const override;
        long long memory_current() const override;
        long long memory_peak() const override;
        long long memory_limit() const override;
        bool is_under_oom() const override;
        long long set_memory_limit(long long bytes) override;
        pid_t spawn(lrun::Cgroup::spawn_arg &arg) override;
    private:
        /**
         * @return  1           exist
         *          0           not exist
         */
        static int exists(const std::string &name);

        /**
         * @param   subsys_id   cgroup subsystem id
         * @param   name        group name
         * @return  full path   "#{path_}/#{name}"
         */
        static std::string path_from_name(subsys_id_t subsys_id, const std::string& name);

        /**
         * @param   subsys_id   cgroup subsystem id
         * @return  full path
         */
        std::string subsys_path(subsys_id_t subsys_id = CG_CPUACCT) const;

        /**
         * set a cgroup property to the same value as parent
         * @param   property    property
         * @return  0           success
         *         <0           failed
         */
        int inherit(subsys_id_t subsys_id, const std::string &property);

        /**
         * cached paths
         */
        static std::string subsys_base_paths_[SUBSYS_COUNT];

        CgroupV1();
    };

    class CgroupV2: public lrun::Cgroup {
    public:
        /**
         * get cgroup mounted path
         * @param   create_on_need  mount cgroup if not mounted
         * @return  cgroup mounted path (first one in mount table)
         */
        static std::string base_path(bool create_on_need = true);

        /**
         * create a cgroup, use existing if possible
         * @return  Cgroup object
         */
        static CgroupV2 create(const std::string& name);

        /**
         * set a cgroup property
         * WARNING: property is not filtered, do not pass untrusted user-generated
         * content here!
         *
         * @param   property    property
         * @param   value       value
         * @return  0           success
         *         <0           failed
         */
        int set(const std::string &property, const std::string &value);

        /**
         * get property
         * @param   property    property
         * @param   max_length  max length to read (not include '\0')
         * @return  string      readed property, empty if fail
         */
        std::string get(const std::string &property, size_t max_length = 255) const;

        /**
         * configure a cgroup with multiple options
         * generally for initialization
         */
        int configure(std::map<std::string, std::string> cgroup_options);

    protected:
        std::string lock_path() const override;
        bool valid() const override;
        void update_output_count() override;
        long long output_usage() const override;
        std::list<pid_t> get_pids() override;
        bool has_pid(pid_t pid) override;
        int freeze(bool freeze = true, int timeout = 5) override;
        int empty() override;
        void killall(bool confirm = true) override;
        int destroy() override;
        int attach(pid_t pid) override;
        int limit_devices() override;
        int reset_usages() override;
        int reset_cpu_usage() override;
        double cpu_usage() const override;
        long long memory_current() const override;
        long long memory_peak() const override;
        long long memory_limit() const override;
        bool is_under_oom() const override;
        long long set_memory_limit(long long bytes) override;
        pid_t spawn(lrun::Cgroup::spawn_arg &arg) override;
    private:
        /**
         * @return  1           exist
         *          0           not exist
         */
        static int exists(const std::string &name);

        /**
        * @param   name        group name
        * @return  full path   "#{path_}/#{name}"
        */
        static std::string path_from_name(const std::string &name);

        /**
         * @return full path of group
         */
        std::string group_path() const;

        /**
         * set a cgroup property to the same value as parent
         * @param   property    property
         * @return  0           success
         *         <0           failed
         */
        int inherit(const std::string &property);

        CgroupV2();
    };

    class CgroupFactory {
    private:
        static constexpr char CG_VERSION_DEST[] = "/var/run/lrun/cg-version";
        static constexpr char CG_VERSION_DIR[] = "/var/run/lrun";

        static int cg_version_;
        static void save();
    public:
        static int cg_version();
        static std::unique_ptr<Cgroup> create(const std::string &name);
    };

    struct Device {
        const char *name;
        unsigned int minor;
        // major is missing because all basic_devices have major = 1
    };

    extern Device basic_devices[5];

    // following functions are called by clone_main_fn

    void do_set_sysctl();
    void do_privatize_filesystem(__attribute__((unused)) const Cgroup::spawn_arg& arg);
    void do_remounts(const Cgroup::spawn_arg& arg);
    void do_mount_bindfs(const Cgroup::spawn_arg& arg);
    void do_chroot(const Cgroup::spawn_arg& arg);
    void do_umount_outside_chroot(const Cgroup::spawn_arg& arg);
    bool should_mount_proc(const Cgroup::spawn_arg& arg);
    bool should_hide_sensitive(const Cgroup::spawn_arg& arg);
    const char * get_proc_fs_type(const Cgroup::spawn_arg& arg);
    void do_mount_proc(const Cgroup::spawn_arg& arg);
    void do_hide_sensitive(const Cgroup::spawn_arg& arg);
    std::list<int> get_fds();
    void do_set_uts(const Cgroup::spawn_arg& arg);
    void do_set_netns(const Cgroup::spawn_arg& arg);
    void do_fd_redirect(int fd_dst, int fd_src);
    void fd_set_cloexec(int fd, int enforce = 1);
    void do_process_fds(const Cgroup::spawn_arg& arg);
    void do_mount_tmpfs(const Cgroup::spawn_arg& arg);
    void do_remount_dev(const Cgroup::spawn_arg& arg);
    void do_chdir(const Cgroup::spawn_arg& arg);
    void do_commands(const Cgroup::spawn_arg& arg);
    void do_renice(const Cgroup::spawn_arg& arg);
    void do_set_umask(const Cgroup::spawn_arg& arg);
    void do_set_uid_gid(const Cgroup::spawn_arg& arg);
    void do_apply_rlimits(const Cgroup::spawn_arg& arg);
    void do_set_env(const Cgroup::spawn_arg& arg);
    void do_seccomp(const Cgroup::spawn_arg& arg);
    void do_set_new_privs(const Cgroup::spawn_arg& arg);
    void init_signal_handler(int signal);
    int clone_init_fn(void *);
    int clone_main_fn(void *clone_arg);
    int is_setns_pidns_supported();
#ifndef NDEBUG
    std::string clone_flags_to_str(int clone_flags);
#endif
}

#endif
