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

#include <couchbase/operations/management/collections.hxx>
#include <couchbase/operations/management/query.hxx>

TEST_CASE("integration: trivial non-data query", "[integration]")
{
    test::utils::integration_test_guard integration;

    if (!integration.cluster_version().supports_gcccp()) {
        test::utils::open_bucket(integration.cluster, integration.ctx.bucket);
    }

    {
        couchbase::operations::query_request req{ R"(SELECT "ruby rules" AS greeting)" };
        auto resp = test::utils::execute(integration.cluster, req);
        INFO(resp.ctx.ec.message())
        REQUIRE_FALSE(resp.ctx.ec);
    }
}

TEST_CASE("integration: query with handler capturing non-copyable object", "[integration]")
{
    test::utils::integration_test_guard integration;

    test::utils::open_bucket(integration.cluster, integration.ctx.bucket);

    if (!integration.cluster_version().supports_gcccp()) {
        test::utils::open_bucket(integration.cluster, integration.ctx.bucket);
    }

    {
        struct move_only_context {
          public:
            explicit move_only_context(std::string input)
              : payload_(std::move(input))
            {
            }
            move_only_context(move_only_context&& other) = default;
            move_only_context& operator=(move_only_context&& other) = default;
            ~move_only_context() = default;

            move_only_context(const move_only_context& other) = delete;
            move_only_context& operator=(const move_only_context& other) = delete;

            [[nodiscard]] const std::string& payload() const
            {
                return payload_;
            }

          private:
            std::string payload_;
        };

        couchbase::operations::query_request req{ R"(SELECT "ruby rules" AS greeting)" };
        auto barrier = std::make_shared<std::promise<couchbase::operations::query_response>>();
        auto f = barrier->get_future();
        move_only_context ctx("foobar");
        auto handler = [barrier, ctx = std::move(ctx)](couchbase::operations::query_response&& resp) {
            CHECK(ctx.payload() == "foobar");
            barrier->set_value(std::move(resp));
        };
        integration.cluster.execute(req, std::move(handler));
        auto resp = f.get();
        INFO(resp.ctx.ec.message())
        REQUIRE_FALSE(resp.ctx.ec);
    }
}

TEST_CASE("integration: query on a collection", "[integration]")
{
    test::utils::integration_test_guard integration;
    if (!integration.cluster_version().supports_collections()) {
        return;
    }
    test::utils::open_bucket(integration.cluster, integration.ctx.bucket);

    auto scope_name = test::utils::uniq_id("scope");
    auto collection_name = test::utils::uniq_id("collection");
    auto index_name = test::utils::uniq_id("index");
    auto key = test::utils::uniq_id("foo");
    tao::json::value value = {
        { "a", 1.0 },
        { "b", 2.0 },
    };
    auto json = couchbase::utils::json::generate(value);

    uint64_t scope_uid;
    uint64_t collection_uid;

    {
        couchbase::operations::management::scope_create_request req{ integration.ctx.bucket, scope_name };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        scope_uid = resp.uid;
    }

    {
        couchbase::operations::management::collection_create_request req{ integration.ctx.bucket, scope_name, collection_name };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        collection_uid = resp.uid;
    }

    auto current_manifest_uid = std::max(collection_uid, scope_uid);
    auto created =
      test::utils::wait_until_collection_manifest_propagated(integration.cluster, integration.ctx.bucket, current_manifest_uid);
    REQUIRE(created);

    {
        couchbase::operations::management::query_index_create_request req{};
        req.bucket_name = integration.ctx.bucket;
        req.scope_name = scope_name;
        req.collection_name = collection_name;
        req.index_name = index_name;
        req.is_primary = true;
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
    }

    couchbase::mutation_token mutation_token;

    {
        couchbase::document_id id{ integration.ctx.bucket, scope_name, collection_name, key };
        couchbase::operations::insert_request req{ id, json };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        mutation_token = resp.token;
    }

    SECTION("correct scope and collection")
    {
        couchbase::operations::query_request req{ fmt::format(R"(SELECT a, b FROM {} WHERE META().id = "{}")", collection_name, key) };
        req.bucket_name = integration.ctx.bucket;
        req.scope_name = scope_name;
        req.mutation_state = { mutation_token };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        REQUIRE(resp.payload.rows.size() == 1);
        REQUIRE(value == couchbase::utils::json::parse(resp.payload.rows[0]));
    }

    SECTION("missing scope")
    {
        couchbase::operations::query_request req{ fmt::format(R"(SELECT a, b FROM {} WHERE META().id = "{}")", collection_name, key) };
        req.bucket_name = integration.ctx.bucket;
        req.scope_name = "missing_scope";
        req.mutation_state = { mutation_token };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE(resp.ctx.ec == couchbase::error::query_errc::index_failure);
    }

    SECTION("missing collection")
    {
        couchbase::operations::query_request req{ fmt::format(R"(SELECT a, b FROM missing_collection WHERE META().id = "{}")", key) };
        req.bucket_name = integration.ctx.bucket;
        req.scope_name = scope_name;
        req.mutation_state = { mutation_token };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE(resp.ctx.ec == couchbase::error::query_errc::index_failure);
    }

    SECTION("prepared")
    {
        couchbase::operations::query_request req{ fmt::format(R"(SELECT a, b FROM {} WHERE META().id = "{}")", collection_name, key) };
        req.bucket_name = integration.ctx.bucket;
        req.scope_name = scope_name;
        req.mutation_state = { mutation_token };
        req.adhoc = false;
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        REQUIRE(resp.payload.rows.size() == 1);
        REQUIRE(value == couchbase::utils::json::parse(resp.payload.rows[0]));
    }
}

TEST_CASE("integration: read only with no results", "[integration]")
{
    test::utils::integration_test_guard integration;

    if (!integration.cluster_version().supports_gcccp()) {
        test::utils::open_bucket(integration.cluster, integration.ctx.bucket);
    }

    {
        couchbase::operations::query_request req{ fmt::format("SELECT * FROM {} LIMIT 0", integration.ctx.bucket) };
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
        REQUIRE(resp.payload.rows.empty());
    }
}

TEST_CASE("integration: invalid query", "[integration]")
{
    test::utils::integration_test_guard integration;

    if (!integration.cluster_version().supports_gcccp()) {
        test::utils::open_bucket(integration.cluster, integration.ctx.bucket);
    }

    {
        couchbase::operations::query_request req{ "I'm not n1ql" };
        auto resp = test::utils::execute(integration.cluster, req);
        INFO(resp.ctx.ec.message());
        REQUIRE(resp.ctx.ec == couchbase::error::common_errc::parsing_failure);
    }
}

TEST_CASE("integration: preserve expiry for mutatation query", "[integration]")
{
    test::utils::integration_test_guard integration;

    if (!integration.cluster_version().supports_preserve_expiry_for_query()) {
        return;
    }

    test::utils::open_bucket(integration.cluster, integration.ctx.bucket);

    couchbase::document_id id{
        integration.ctx.bucket,
        "_default",
        "_default",
        test::utils::uniq_id("preserve_expiry_for_query"),
    };

    uint32_t expiry = std::numeric_limits<uint32_t>::max();
    const char* expiry_path = "$document.exptime";

    {
        couchbase::operations::upsert_request req{ id, R"({"foo":42})" };
        req.expiry = expiry;
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
    }

    {
        couchbase::operations::lookup_in_request req{ id };
        req.specs.add_spec(couchbase::protocol::subdoc_opcode::get, true, expiry_path);
        req.specs.add_spec(couchbase::protocol::subdoc_opcode::get, false, "foo");
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE(expiry == std::stoul(resp.fields[0].value));
        REQUIRE("42" == resp.fields[1].value);
    }

    {
        std::string statement = fmt::format("UPDATE {} AS b USE KEYS '{}' SET b.foo = 43", integration.ctx.bucket, id.key());
        couchbase::operations::query_request req{ statement };
        req.preserve_expiry = true;
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE_FALSE(resp.ctx.ec);
    }

    {
        couchbase::operations::lookup_in_request req{ id };
        req.specs.add_spec(couchbase::protocol::subdoc_opcode::get, true, expiry_path);
        req.specs.add_spec(couchbase::protocol::subdoc_opcode::get, false, "foo");
        auto resp = test::utils::execute(integration.cluster, req);
        REQUIRE(expiry == std::stoul(resp.fields[0].value));
        REQUIRE("43" == resp.fields[1].value);
    }
}
