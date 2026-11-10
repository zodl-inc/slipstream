# Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of ZODL Slipstream.
#
# ZODL Slipstream is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License,
# version 3 only, as published by the Free Software Foundation.
#
# ZODL Slipstream is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# Commercial licensing: see COMMERCIAL-LICENSE.md.

require "yaml"

root = File.expand_path("../..", __dir__)
ci = File.join(root, ".github/workflows/ci.yml")
workflow = YAML.load_file(ci)
cargo_jobs = workflow.fetch("jobs").select do |_, job|
  job.fetch("steps", []).any? { |step| step.fetch("run", "").match?(/\bcargo (test|check|clippy|doc)\b/) }
end
raise "no Cargo jobs checked" if cargo_jobs.empty?
# zodl-ohttp-client comes from crates.io, so no job needs a token to fetch it.
cargo_jobs.each do |name, job|
  if job.fetch("steps").any? { |step| step.fetch("uses", "").include?("authorize-private-ohttp") }
    raise "#{name}: still mints a token for the public zodl-ohttp repository"
  end
end
raise "the private OHTTP authorization action remains" if Dir.exist?(File.join(root, ".github/actions/authorize-private-ohttp"))
# The forbidden name is built from two parts so that this file itself stays clear of the repo-wide grep.
raise "OHTTP build-time configuration remains in the workflow" if File.read(ci, encoding: "UTF-8").include?("ZODL_" + "OHTTP")
manifest = File.read(File.join(root, "core/Cargo.toml"), encoding: "UTF-8")
lock = File.read(File.join(root, "Cargo.lock"), encoding: "UTF-8")
raise "old dependency URL" if [manifest, lock].any? { |text| text.include?("https://github.com/zodl-inc/ohttp.git") }
# From crates.io, slipstream stays publishable there (cargo publish refuses git dependencies).
raise "zodl-ohttp-client still comes from git" if [manifest, lock].any? { |text| text.include?("github.com/zodl-inc/zodl-ohttp") }
dependency = manifest[/^zodl-ohttp-client = .*$/]
raise "zodl-ohttp-client is not the crates.io 1.0.1 release" unless dependency&.include?('version = "1.0.1"')
locked = lock[/^\[\[package\]\]\nname = "zodl-ohttp-client"\n.*?\n\n/m]
unless locked&.include?('version = "1.0.1"') && locked.include?('source = "registry+https://github.com/rust-lang/crates.io-index"')
  raise "Cargo.lock does not resolve zodl-ohttp-client 1.0.1 from crates.io"
end
puts "OHTTP workflow contract: #{cargo_jobs.length} Cargo jobs need no private token; zodl-ohttp-client 1.0.1 comes from crates.io"
