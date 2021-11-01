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

#include "test_helper_native.hxx"

#include <couchbase/operations/management/bucket.hxx>
#include <couchbase/operations/management/collections.hxx>
#include <couchbase/operations/management/user.hxx>

using namespace couchbase::operations::management;

std::string
uniq_id(const std::string& prefix)
{
    return fmt::format("{}_{}", prefix, std::chrono::steady_clock::now().time_since_epoch().count());
}

TEST_CASE("native: bucket management", "[native]")
{
    auto ctx = test_context::load_from_environment();
    native_init_logger();

    auto connstr = couchbase::utils::parse_connection_string(ctx.connection_string);
    couchbase::cluster_credentials auth{};
    auth.username = ctx.username;
    auth.password = ctx.password;

    asio::io_context io;

    couchbase::cluster cluster(io);
    auto io_thread = std::thread([&io]() { io.run(); });

    open_cluster(cluster, couchbase::origin(auth, connstr));

    auto bucket_name = uniq_id("bucket");
    bucket_settings bucket_settings;
    bucket_settings.name = bucket_name;
    bucket_settings.ram_quota_mb = 100;
    bucket_settings.num_replicas = 1;
    bucket_settings.bucket_type = bucket_settings::bucket_type::couchbase;
    bucket_settings.eviction_policy = bucket_settings::eviction_policy::value_only;
    bucket_settings.flush_enabled = true;
    bucket_settings.max_expiry = 10;
    bucket_settings.compression_mode = bucket_settings::compression_mode::active;
    bucket_settings.replica_indexes = true;
    bucket_settings.conflict_resolution_type = bucket_settings::conflict_resolution_type::sequence_number;

    {
        bucket_create_request req;
        req.bucket = bucket_settings;
        auto resp = execute_http(cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
    }

    {
        bucket_get_request req{ bucket_name };
        auto resp = execute_http(cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        REQUIRE(bucket_settings.bucket_type == resp.bucket.bucket_type);
        REQUIRE(bucket_settings.name == resp.bucket.name);
        REQUIRE(bucket_settings.ram_quota_mb == resp.bucket.ram_quota_mb);
        REQUIRE(bucket_settings.num_replicas == resp.bucket.num_replicas);
        REQUIRE(bucket_settings.flush_enabled == resp.bucket.flush_enabled);
        REQUIRE(bucket_settings.max_expiry == resp.bucket.max_expiry);
        REQUIRE(bucket_settings.eviction_policy == resp.bucket.eviction_policy);
        REQUIRE(bucket_settings.compression_mode == resp.bucket.compression_mode);
        REQUIRE(bucket_settings.replica_indexes == resp.bucket.replica_indexes);
    }

    {
        bucket_get_all_request req{};
        auto resp = execute_http(cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        bool found = false;
        for (const auto& bucket : resp.buckets) {
            if (bucket.name != bucket_name) {
                continue;
            }
            found = true;
            REQUIRE(bucket_settings.bucket_type == bucket.bucket_type);
            REQUIRE(bucket_settings.name == bucket.name);
            REQUIRE(bucket_settings.ram_quota_mb == bucket.ram_quota_mb);
            REQUIRE(bucket_settings.num_replicas == bucket.num_replicas);
            REQUIRE(bucket_settings.flush_enabled == bucket.flush_enabled);
            REQUIRE(bucket_settings.max_expiry == bucket.max_expiry);
            REQUIRE(bucket_settings.eviction_policy == bucket.eviction_policy);
            REQUIRE(bucket_settings.compression_mode == bucket.compression_mode);
            REQUIRE(bucket_settings.replica_indexes == bucket.replica_indexes);
            break;
        }
        REQUIRE(found);
    }

    {
        bucket_drop_request req{ bucket_name };
        auto resp = execute_http(cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
    }

    {
        bucket_get_request req{ bucket_name };
        auto resp = execute_http(cluster, req);
        REQUIRE(resp.ctx.ec == couchbase::error::common_errc::bucket_not_found);
    }

    close_cluster(cluster);

    io_thread.join();
}

TEST_CASE("native: collection management", "[native]")
{
    auto ctx = test_context::load_from_environment();
    native_init_logger();

    if (!ctx.version.supports_collections()) {
        return;
    }

    auto connstr = couchbase::utils::parse_connection_string(ctx.connection_string);
    couchbase::cluster_credentials auth{};
    auth.username = ctx.username;
    auth.password = ctx.password;

    asio::io_context io;

    couchbase::cluster cluster(io);
    auto io_thread = std::thread([&io]() { io.run(); });

    open_cluster(cluster, couchbase::origin(auth, connstr));

    SECTION("crud")
    {

        auto scope_name = uniq_id("scope");
        auto collection_name = uniq_id("collection");

        {
            scope_create_request req{ ctx.bucket, scope_name };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
        {
            scope_create_request req{ ctx.bucket, scope_name };
            auto resp = execute_http(cluster, req);
            REQUIRE(resp.ctx.ec == couchbase::error::management_errc::scope_exists);
        }
        {
            collection_create_request req{ ctx.bucket, scope_name, collection_name, 5 };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
        {
            collection_create_request req{ ctx.bucket, scope_name, collection_name };
            auto resp = execute_http(cluster, req);
            REQUIRE(resp.ctx.ec == couchbase::error::management_errc::collection_exists);
        }
        {
            scope_get_all_request req{ ctx.bucket };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
            bool found = false;
            for (const auto& scope : resp.manifest.scopes) {
                if (scope.name != scope_name) {
                    continue;
                }
                found = true;
                REQUIRE(scope.collections.size() == 1);
                auto col = scope.collections[0];
                REQUIRE(collection_name == col.name);
                REQUIRE(scope_name == col.scope_name);
                // REQUIRE(5 == col.max_expiry);
                break;
            }
            REQUIRE(found);
        }
        {
            collection_drop_request req{ ctx.bucket, scope_name, collection_name };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
        {
            collection_drop_request req{ ctx.bucket, scope_name, collection_name };
            auto resp = execute_http(cluster, req);
            REQUIRE(resp.ctx.ec == couchbase::error::common_errc::collection_not_found);
        }
        {
            scope_drop_request req{ ctx.bucket, scope_name };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
        {
            scope_drop_request req{ ctx.bucket, scope_name };
            auto resp = execute_http(cluster, req);
            REQUIRE(resp.ctx.ec == couchbase::error::common_errc::scope_not_found);
        }
    }

    close_cluster(cluster);

    io_thread.join();
}

TEST_CASE("native: user management", "[native]")
{
    auto ctx = test_context::load_from_environment();
    native_init_logger();

    if (!ctx.version.supports_collections()) {
        return;
    }

    auto connstr = couchbase::utils::parse_connection_string(ctx.connection_string);
    couchbase::cluster_credentials auth{};
    auth.username = ctx.username;
    auth.password = ctx.password;

    asio::io_context io;

    couchbase::cluster cluster(io);
    auto io_thread = std::thread([&io]() { io.run(); });

    open_cluster(cluster, couchbase::origin(auth, connstr));

    SECTION("group crud")
    {

        auto group_name_1 = uniq_id("group");
        auto group_name_2 = uniq_id("group");

        rbac::group group{};
        group.name = group_name_1;
        group.description = "this is a test";
        group.roles = { rbac::role{ "replication_target", ctx.bucket }, rbac::role{ "replication_admin" } };
        group.ldap_group_reference = "asda=price";

        {
            group_upsert_request req{ group };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
        {
            group_get_request req{ group_name_1 };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE(resp.group.name == group.name);
            REQUIRE(resp.group.description == group.description);
            REQUIRE(resp.group.ldap_group_reference == group.ldap_group_reference);
        }
        {
            group.description = "this is still a test";
            group.roles.push_back(rbac::role{ "query_system_catalog" });
            group_upsert_request req{ group };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
        {
            group.name = group_name_2;
            group_upsert_request req{ group };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
        {
            group_get_all_request req{};
            auto resp = execute_http(cluster, req);
            INFO(resp.ctx.ec.message());
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE(resp.groups.size() >= 2);
        }
        {
            role_get_all_request req{};
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE(resp.roles.size() > 0);
        }
        {
            group_drop_request req{ group_name_1 };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
        {
            group_drop_request req{ group_name_2 };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
    }

    close_cluster(cluster);

    io_thread.join();
}