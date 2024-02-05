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

#include "cgroup.h"
#include "utils/for_each.h"
#include "utils/fs.h"

using namespace lrun;

using std::string;

int CgroupFactory::cg_version_ = 0;
int CgroupFactory::cg_version() {
    if (cg_version_ != 0) {
        return cg_version_;
    }
    std::map<string, fs::MountEntry> mounts = fs::get_mounts();
    FOR_EACH_CONST(p, mounts) {
        const fs::MountEntry& ent = p.second;
        if (ent.type == string(fs::TYPE_CGROUP)) return cg_version_ = 1;
    }
    FOR_EACH_CONST(p, mounts) {
        const fs::MountEntry& ent = p.second;
        if (ent.type == string(fs::TYPE_CGROUP2)) return cg_version_ = 2;
    }
    string available_filesystem = fs::read("/proc/filesystem", 4096);
    if (available_filesystem.find("cgroup") != string::npos) {
        return cg_version_ = 1;
    }
    if (available_filesystem.find("cgroup2") != string::npos) {
        return cg_version_ = 2;
    }
    FATAL("cannot determine cgroup version");
}

std::unique_ptr<Cgroup> CgroupFactory::create(const std::string &name) {
    switch (cg_version()) {
        case 1:
            return std::make_unique<CgroupV1>(CgroupV1::create(name));
        case 2:
            return std::make_unique<CgroupV2>(CgroupV2::create(name));
        default:
            FATAL("cannot determine cgroup version");
    }
}