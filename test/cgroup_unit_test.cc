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

#include "../src/cgroup.h"
#include "test.h"

using namespace lrun;

TESTCASE(get_path) {
    if (CgroupFactory::cg_version() == 1) {
        CHECK(!CgroupV1::base_path(CgroupV1::CG_CPUACCT, true).empty());
    }
    if (CgroupFactory::cg_version() == 2) {
        CHECK(!CgroupV2::base_path(true).empty());
    }
}

TESTCASE(create_and_destroy) {
    std::unique_ptr<Cgroup> pcg = CgroupFactory::create("testcreate");
    Cgroup& cg = *pcg;
    CHECK(cg.valid());
    CHECK(cg.destroy() == 0);
    CHECK(cg.valid() == false);
}

TESTCASE(set_properties) {
    std::unique_ptr<Cgroup> pcg = CgroupFactory::create("testcreate");
    Cgroup& base_cg = *pcg;
    // FIXME assume no swap here
    if (base_cg.version() == 1) {
        auto &cg = dynamic_cast<CgroupV1 &>(base_cg);
        CHECK(cg.set(CgroupV1::CG_MEMORY, "memory.limit_in_bytes", "1048576") == 0);
        CHECK(cg.get(CgroupV1::CG_MEMORY, "memory.limit_in_bytes") == "1048576\n");
    }
    if (base_cg.version() == 2) {
        auto &cg = dynamic_cast<CgroupV2 &>(base_cg);
        CHECK(cg.set("memory.max", "1048576") == 0);
        CHECK(cg.get("memory.max") == "1048576\n");
    }
    CHECK(base_cg.reset_usages() == 0);
    CHECK(base_cg.destroy() == 0);
}

TESTCASE(create_use_exist) {
    std::unique_ptr<Cgroup> pcg1 = CgroupFactory::create("testexist");
    std::unique_ptr<Cgroup> pcg2 = CgroupFactory::create("testexist");
    Cgroup& cg1 = *pcg1;
    Cgroup& cg2 = *pcg2;
    CHECK(cg1.valid());
    CHECK(cg2.valid());
    CHECK(cg2.destroy() == 0);
    CHECK(!cg1.valid());
}


