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
#include "utils/strconv.h"

using namespace lrun;

using std::string;

int CgroupFactory::cg_version_ = 0;
int CgroupFactory::cg_version() {
    if (cg_version_ != 0) {
        return cg_version_;
    }
    string cached = fs::read(CG_VERSION_DEST, 8);
    if (!cached.empty()) {
        return cg_version_ = strconv::to_int(cached);
    }
    std::map<string, fs::MountEntry> mounts = fs::get_mounts();
    FOR_EACH_CONST(p, mounts) {
        const fs::MountEntry& ent = p.second;
        if (ent.type == string(fs::TYPE_CGROUP)) {
            cg_version_ = 1;
            save();
            return cg_version_;
        }
    }
    FOR_EACH_CONST(p, mounts) {
        const fs::MountEntry& ent = p.second;
        if (ent.type == string(fs::TYPE_CGROUP2)) {
            cg_version_ = 2;
            save();
            return cg_version_;
        }
    }
    string available_filesystem = fs::read("/proc/filesystem", 4096);
    if (available_filesystem.find("cgroup") != string::npos) {
        cg_version_ = 1;
        save();
        return cg_version_;
    }
    if (available_filesystem.find("cgroup2") != string::npos) {
        cg_version_ = 2;
        save();
        return cg_version_;
    }
    FATAL("cannot determine cgroup version");
}

void CgroupFactory::save() {
    fs::mkdir_p(CG_VERSION_DIR, /* mode */ 0755);
    fs::write(CG_VERSION_DEST, strconv::from_int(cg_version_));
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
