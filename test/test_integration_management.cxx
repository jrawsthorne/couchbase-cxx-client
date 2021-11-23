/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *   Copyright 2020-2021 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "test_helper_integration.hxx"

#include <couchbase/operations/management/bucket.hxx>
#include <couchbase/operations/management/user.hxx>
#include <couchbase/operations/management/collections.hxx>

TEST_CASE("integration: bucket management", "[integration]")
{
    test::utils::integration_test_guard integration;

    if (!integration.ctx.version.supports_gcccp()) {
        test::utils::open_bucket(integration.cluster, integration.ctx.bucket);
    }

    auto bucket_name = test::utils::uniq_id("bucket");

    {
        couchbase::operations::management::bucket_create_request req;
        req.bucket.name = bucket_name;
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
    }

    {
        auto created = test::utils::wait_until([&integration, bucket_name]() {
            couchbase::operations::management::bucket_get_request req{ bucket_name };
            auto resp = test::utils::execute(integration.cluster, req);
            return !resp.ctx.ec;
        });
        REQUIRE(created);
    }

    {
        couchbase::operations::management::bucket_get_all_request req;
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        REQUIRE(!resp.buckets.empty());
        auto known_buckets =
          std::count_if(resp.buckets.begin(), resp.buckets.end(), [bucket_name](const auto& entry) { return entry.name == bucket_name; });
        REQUIRE(known_buckets > 0);
    }

    {
        couchbase::operations::management::bucket_drop_request req{ bucket_name };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
    }

    {
        auto dropped = test::utils::wait_until([&integration, bucket_name]() {
            couchbase::operations::management::bucket_get_request req{ bucket_name };
            auto resp = test::utils::execute(integration.cluster, req);
            return resp.ctx.ec == couchbase::error::common_errc::bucket_not_found;
        });
        REQUIRE(dropped);
    }

    {
        couchbase::operations::management::bucket_get_all_request req;
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE(!resp.buckets.empty());
        auto known_buckets =
          std::count_if(resp.buckets.begin(), resp.buckets.end(), [bucket_name](const auto& entry) { return entry.name == bucket_name; });
        REQUIRE(known_buckets == 0);
    }
}

void
assert_user_and_metadata(const couchbase::operations::management::rbac::user_and_metadata& user,
                         const couchbase::operations::management::rbac::user_and_metadata& expected)
{
    REQUIRE(user.username == expected.username);
    REQUIRE(user.groups == expected.groups);
    REQUIRE(user.roles.size() == expected.roles.size());
    for (size_t i = 0; i < user.roles.size(); ++i) {
        REQUIRE(user.roles[i].name == expected.roles[i].name);
        REQUIRE(user.roles[i].bucket == expected.roles[i].bucket);
        REQUIRE(user.roles[i].scope == expected.roles[i].scope);
        REQUIRE(user.roles[i].collection == expected.roles[i].collection);
    }
    REQUIRE(user.display_name == expected.display_name);
    REQUIRE(user.domain == expected.domain);
    REQUIRE(user.effective_roles.size() == expected.effective_roles.size());
    for (size_t i = 0; i < user.effective_roles.size(); ++i) {
        REQUIRE(user.effective_roles[i].name == expected.effective_roles[i].name);
        REQUIRE(user.effective_roles[i].bucket == expected.effective_roles[i].bucket);
        REQUIRE(user.effective_roles[i].scope == expected.effective_roles[i].scope);
        REQUIRE(user.effective_roles[i].collection == expected.effective_roles[i].collection);
        REQUIRE(user.effective_roles[i].origins.size() == expected.effective_roles[i].origins.size());
        for (size_t j = 0; j < user.effective_roles[i].origins.size(); ++j) {
            REQUIRE(user.effective_roles[i].origins[j].name == expected.effective_roles[i].origins[j].name);
            REQUIRE(user.effective_roles[i].origins[j].type == expected.effective_roles[i].origins[j].type);
        }
    }
}

TEST_CASE("integration: user management", "[integration]")
{
    test::utils::integration_test_guard integration;

    if (!integration.ctx.version.supports_gcccp()) {
        test::utils::open_bucket(integration.cluster, integration.ctx.bucket);
    }

    SECTION("group crud")
    {
        auto group_name_1 = test::utils::uniq_id("group");
        auto group_name_2 = test::utils::uniq_id("group");

        couchbase::operations::management::rbac::group group{};
        group.name = group_name_1;
        group.description = "this is a test";
        group.roles = { couchbase::operations::management::rbac::role{ "replication_target", integration.ctx.bucket },
                        couchbase::operations::management::rbac::role{ "replication_admin" } };
        group.ldap_group_reference = "asda=price";

        {
            couchbase::operations::management::group_upsert_request req{ group };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            couchbase::operations::management::group_get_request req{ group_name_1 };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE(resp.group.name == group.name);
            REQUIRE(resp.group.description == group.description);
            REQUIRE(resp.group.ldap_group_reference == group.ldap_group_reference);
        }

        {
            group.description = "this is still a test";
            group.roles.push_back(couchbase::operations::management::rbac::role{ "query_system_catalog" });
            couchbase::operations::management::group_upsert_request req{ group };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            group.name = group_name_2;
            couchbase::operations::management::group_upsert_request req{ group };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            couchbase::operations::management::group_get_all_request req{};
            auto resp = test::utils::execute(integration.cluster, req);
            INFO(resp.ctx.ec.message());
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE(resp.groups.size() >= 2);
        }

        {
            couchbase::operations::management::role_get_all_request req{};
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE(resp.roles.size() > 0);
        }

        {
            couchbase::operations::management::group_drop_request req{ group_name_1 };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            couchbase::operations::management::group_drop_request req{ group_name_2 };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
    }

    SECTION("get missing group")
    {
        couchbase::operations::management::group_get_request req{ test::utils::uniq_id("group") };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE(resp.ctx.ec == couchbase::error::management_errc::group_not_found);
    }

    SECTION("drop missing group")
    {

        couchbase::operations::management::group_drop_request req{ test::utils::uniq_id("group") };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE(resp.ctx.ec == couchbase::error::management_errc::group_not_found);
    }

    SECTION("user and groups crud")
    {
        auto group_name = test::utils::uniq_id("group");
        auto user_name = test::utils::uniq_id("user");

        couchbase::operations::management::rbac::group group{};
        group.name = group_name;
        group.description = "this is a test";
        group.roles = { couchbase::operations::management::rbac::role{ "replication_target", integration.ctx.bucket },
                        couchbase::operations::management::rbac::role{ "replication_admin" } };

        {
            couchbase::operations::management::group_upsert_request req{ group };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        couchbase::operations::management::rbac::user user{ user_name };
        user.display_name = "display_name";
        user.password = "password";
        user.roles = {
            couchbase::operations::management::rbac::role{ "bucket_admin", integration.ctx.bucket },
        };
        user.groups = { group_name };

        {
            couchbase::operations::management::user_upsert_request req{};
            req.user = user;
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        couchbase::operations::management::rbac::user_and_metadata expected{};
        expected.username = user.username;
        expected.display_name = user.display_name;
        expected.roles = user.roles;
        expected.groups = user.groups;
        expected.domain = couchbase::operations::management::rbac::auth_domain::local;

        couchbase::operations::management::rbac::role_and_origins expected_role_1{};
        expected_role_1.name = "bucket_admin";
        expected_role_1.bucket = integration.ctx.bucket;
        expected_role_1.origins = { couchbase::operations::management::rbac::origin{ "user" } };

        couchbase::operations::management::rbac::role_and_origins expected_role_2{};
        expected_role_2.name = "replication_target";
        expected_role_2.bucket = integration.ctx.bucket;
        expected_role_2.origins = { couchbase::operations::management::rbac::origin{ "group", group_name } };

        couchbase::operations::management::rbac::role_and_origins expected_role_3{};
        expected_role_3.name = "replication_admin";
        expected_role_3.origins = { couchbase::operations::management::rbac::origin{ "group", group_name } };

        expected.effective_roles = { expected_role_1, expected_role_2, expected_role_3 };

        {
            couchbase::operations::management::user_get_request req{ user_name };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);

            assert_user_and_metadata(resp.user, expected);
        };

        user.display_name = "different_display_name";
        expected.display_name = "different_display_name";

        {
            couchbase::operations::management::user_upsert_request req{};
            req.user = user;
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            couchbase::operations::management::user_get_request req{ user_name };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);

            assert_user_and_metadata(resp.user, expected);
        };

        {
            couchbase::operations::management::user_get_all_request req{};
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE_FALSE(resp.users.empty());
            auto upserted_user =
              std::find_if(resp.users.begin(), resp.users.end(), [&user_name](const auto& u) { return u.username == user_name; });
            REQUIRE(upserted_user != resp.users.end());
            assert_user_and_metadata(*upserted_user, expected);
        }

        {
            couchbase::operations::management::user_drop_request req{ user_name };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            couchbase::operations::management::group_drop_request req{ group_name };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            couchbase::operations::management::user_get_request req{ user_name };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE(resp.ctx.ec == couchbase::error::management_errc::user_not_found);
        }
    }

    SECTION("get roles")
    {
        couchbase::operations::management::role_get_all_request req{};
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        REQUIRE(resp.roles.size() > 0);
    }

    SECTION("collections roles")
    {
        auto scope_name = test::utils::uniq_id("scope");
        auto collection_name = test::utils::uniq_id("collection");
        auto user_name = test::utils::uniq_id("user");

        {
            couchbase::operations::management::scope_create_request req{ integration.ctx.bucket, scope_name };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            couchbase::operations::management::collection_create_request req{ integration.ctx.bucket, scope_name, collection_name };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        // TODO: Use wait_until_collection_manifest_propagated from https://github.com/couchbaselabs/couchbase-cxx-client/pull/55 when
        // merged

        couchbase::operations::management::rbac::user user{ user_name };
        user.display_name = "display_name";
        user.password = "password";
        user.roles = {
            couchbase::operations::management::rbac::role{ "data_reader", integration.ctx.bucket, scope_name },
        };

        {
            couchbase::operations::management::user_upsert_request req{};
            req.user = user;
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            couchbase::operations::management::user_get_request req{ user_name };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE(resp.user.roles.size() == 1);
            REQUIRE(resp.user.roles[0].name == "data_reader");
            REQUIRE(resp.user.roles[0].bucket == integration.ctx.bucket);
            REQUIRE(resp.user.roles[0].scope == scope_name);
        };

        user.roles = {
            couchbase::operations::management::rbac::role{ "data_reader", integration.ctx.bucket, scope_name, collection_name },
        };

        {
            couchbase::operations::management::user_upsert_request req{};
            req.user = user;
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            couchbase::operations::management::user_get_request req{ user_name };
            auto resp = test::utils::execute(integration.cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE(resp.user.roles.size() == 1);
            REQUIRE(resp.user.roles[0].name == "data_reader");
            REQUIRE(resp.user.roles[0].bucket == integration.ctx.bucket);
            REQUIRE(resp.user.roles[0].scope == scope_name);
            REQUIRE(resp.user.roles[0].collection == collection_name);
        };
    }
}
