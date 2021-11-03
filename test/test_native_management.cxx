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

using namespace couchbase::operations;
using namespace management;

std::string
uniq_id(const std::string& prefix)
{
    return fmt::format("{}_{}", prefix, std::chrono::steady_clock::now().time_since_epoch().count());
}

class ClusterTest
{
  public:
    std::thread io_thread;
    asio::io_context io;
    couchbase::cluster cluster;
    test_context ctx;
    ClusterTest()
      : cluster(couchbase::cluster(io))
      , ctx(test_context::load_from_environment())
    {
        native_init_logger();
        auto connstr = couchbase::utils::parse_connection_string(ctx.connection_string);
        couchbase::cluster_credentials auth{};
        auth.username = ctx.username;
        auth.password = ctx.password;
        io_thread = std::thread([this]() { io.run(); });
        open_cluster(cluster, couchbase::origin(auth, connstr));
        open_bucket(cluster, ctx.bucket);
    }
    ~ClusterTest()
    {
        close_cluster(cluster);
        io_thread.join();
    }
};

#define REQUIRE_FALSE_HTTP(resp)                                                                                                           \
    INFO(resp.ctx.ec.message());                                                                                                           \
    REQUIRE_FALSE(resp.ctx.ec);

#define REQUIRE_FALSE_HTTP_ERR(resp)                                                                                                       \
    INFO(resp.ctx.ec.message());                                                                                                           \
    INFO(resp.error_message);                                                                                                              \
    REQUIRE_FALSE(resp.ctx.ec);

TEST_CASE_METHOD(ClusterTest, "native: bucket management", "[native]")
{

    auto bucket_name = uniq_id("bucket");

    SECTION("crud")
    {
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
            REQUIRE_FALSE_HTTP_ERR(resp);
        }

        {
            bucket_get_request req{ bucket_name };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE_HTTP(resp);
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
            REQUIRE_FALSE_HTTP(resp);
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
            bucket_settings.ram_quota_mb += 1;
            bucket_update_request req;
            req.bucket = bucket_settings;
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE_HTTP_ERR(resp);
        }

        {
            bucket_get_request req{ bucket_name };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE_HTTP(resp);
            REQUIRE(bucket_settings.ram_quota_mb == resp.bucket.ram_quota_mb);
        }

        {
            bucket_drop_request req{ bucket_name };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE_HTTP(resp);
        }

        {
            bucket_get_request req{ bucket_name };
            auto resp = execute_http(cluster, req);
            REQUIRE(resp.ctx.ec == couchbase::error::common_errc::bucket_not_found);
        }

        {
            bucket_get_all_request req;
            auto resp = execute_http(cluster, req);
            REQUIRE(!resp.buckets.empty());
            auto known_buckets =
              std::count_if(resp.buckets.begin(), resp.buckets.end(), [bucket_name](auto& entry) { return entry.name == bucket_name; });
            REQUIRE(known_buckets == 0);
        }
    }

    SECTION("flush")
    {
        REQUIRE_FALSE(false);
        SECTION("flush item")
        {
            couchbase::document_id id{ bucket_name, "_default._default", uniq_id("foo") };

            {
                bucket_create_request req;
                req.bucket.name = bucket_name;
                req.bucket.flush_enabled = true;
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }

            wait_until_bucket_healthy(cluster, bucket_name);

            open_bucket(cluster, bucket_name);

            {
                const tao::json::value value = {
                    { "a", 1.0 },
                };
                insert_request req{ id, tao::json::to_string(value) };
                auto resp = execute(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }

            {
                get_request req{ id };
                auto resp = execute(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }

            {
                bucket_flush_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }

            auto& c = cluster;

            wait_until_condition([&c, id]() {
                return false;
                // get_request req{ id };
                // auto resp = execute(cluster, req);
                // return resp.ctx.ec == couchbase::error::key_value_errc::document_not_found;
            });

            {
                bucket_drop_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }
        }

        SECTION("no bucket")
        {
            bucket_flush_request req{ bucket_name };
            auto resp = execute_http(cluster, req);
            REQUIRE(resp.ctx.ec == couchbase::error::common_errc::bucket_not_found);
        }

        SECTION("flush disabled")
        {
            {
                bucket_create_request req;
                req.bucket.name = bucket_name;
                req.bucket.flush_enabled = false;
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }

            {
                bucket_flush_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE(resp.ctx.ec == couchbase::error::management_errc::bucket_not_flushable);
            }

            {
                bucket_drop_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }
        }
    }

    SECTION("memcached")
    {
        REQUIRE_FALSE(false);
        {
            bucket_settings bucket_settings{};
            bucket_settings.name = bucket_name;
            bucket_settings.bucket_type = bucket_settings::bucket_type::memcached;
            bucket_settings.num_replicas = 0;
            bucket_create_request req{ bucket_settings };
            auto resp = execute_http(cluster, req);
            INFO(resp.ctx.ec.message());
            REQUIRE_FALSE(resp.ctx.ec);
        }

        {
            bucket_get_request req{ bucket_name };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
            REQUIRE(resp.bucket.bucket_type == bucket_settings::bucket_type::memcached);
        }

        {
            bucket_drop_request req{ bucket_name };
            auto resp = execute_http(cluster, req);
            REQUIRE_FALSE(resp.ctx.ec);
        }
    }

    SECTION("ephemeral")
    {
        bucket_settings bucket_settings;
        bucket_settings.name = bucket_name;
        bucket_settings.bucket_type = bucket_settings::bucket_type::ephemeral;
        REQUIRE_FALSE(false);

        SECTION("default eviction")
        {
            {

                bucket_create_request req{ bucket_settings };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE_HTTP(resp);
            }

            {
                bucket_get_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
                REQUIRE(resp.bucket.bucket_type == bucket_settings::bucket_type::ephemeral);
                REQUIRE(resp.bucket.eviction_policy == bucket_settings::eviction_policy::no_eviction);
            }

            {
                bucket_drop_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }
        }

        SECTION("nru eviction")
        {
            {
                bucket_settings.eviction_policy = bucket_settings::eviction_policy::not_recently_used;
                bucket_create_request req{ bucket_settings };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }

            {
                bucket_get_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
                REQUIRE(resp.bucket.bucket_type == bucket_settings::bucket_type::ephemeral);
                REQUIRE(resp.bucket.eviction_policy == bucket_settings::eviction_policy::not_recently_used);
            }

            {
                bucket_drop_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }
        }
    }

    SECTION("couchbase")
    {
        bucket_settings bucket_settings;
        bucket_settings.name = bucket_name;
        bucket_settings.bucket_type = bucket_settings::bucket_type::couchbase;

        REQUIRE_FALSE(false);

        SECTION("default eviction")
        {
            {

                bucket_create_request req{ bucket_settings };
                auto resp = execute_http(cluster, req);
                INFO(resp.error_message);
                REQUIRE_FALSE(resp.ctx.ec);
            }

            {
                bucket_get_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
                REQUIRE(resp.bucket.bucket_type == bucket_settings::bucket_type::couchbase);
                REQUIRE(resp.bucket.eviction_policy == bucket_settings::eviction_policy::value_only);
            }

            {
                bucket_drop_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }
        }

        SECTION("full eviction")
        {
            {
                bucket_settings.eviction_policy = bucket_settings::eviction_policy::full;
                bucket_create_request req{ bucket_settings };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }

            {
                bucket_get_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
                REQUIRE(resp.bucket.bucket_type == bucket_settings::bucket_type::couchbase);
                REQUIRE(resp.bucket.eviction_policy == bucket_settings::eviction_policy::full);
            }

            {
                bucket_drop_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }
        }
    }

    SECTION("update no bucket")
    {
        {
            bucket_settings bucket_settings;
            bucket_settings.name = bucket_name;
            bucket_update_request req;
            req.bucket = bucket_settings;
            auto resp = execute_http(cluster, req);
            REQUIRE(resp.ctx.ec == couchbase::error::common_errc::bucket_not_found);
        }
    }

    SECTION("minimum durability level")
    {
        bucket_settings bucket_settings;
        bucket_settings.name = bucket_name;

        REQUIRE_FALSE(false);

        SECTION("default")
        {
            {
                bucket_create_request req{ bucket_settings };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }

            {
                bucket_get_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
                REQUIRE(resp.bucket.minimum_durability_level == couchbase::protocol::durability_level::none);
            }

            {
                bucket_drop_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }
        }

        SECTION("majority")
        {
            {
                bucket_settings.minimum_durability_level = couchbase::protocol::durability_level::majority;
                bucket_create_request req{ bucket_settings };
                auto resp = execute_http(cluster, req);
                INFO(resp.error_message);
                INFO(resp.ctx.ec.message());
                REQUIRE_FALSE(resp.ctx.ec);
            }

            {
                bucket_get_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
                REQUIRE(resp.bucket.minimum_durability_level == couchbase::protocol::durability_level::majority);
            }

            {
                bucket_drop_request req{ bucket_name };
                auto resp = execute_http(cluster, req);
                REQUIRE_FALSE(resp.ctx.ec);
            }
        }
    }
}
