window.BENCHMARK_DATA = {
  "lastUpdate": 1790364441569,
  "repoUrl": "https://github.com/mangrisano/certinspect",
  "entries": {
    "certinspect benchmarks": [
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "e3fd33f88fb52c00a41657d922764ed80f6d3c55",
          "message": "ci: add performance benchmark workflow and badge",
          "timestamp": "2026-07-31T23:21:36+02:00",
          "tree_id": "f5e6d84ad1aff0f892a3404b93e88041346c1ce4",
          "url": "https://github.com/mangrisano/certinspect/commit/e3fd33f88fb52c00a41657d922764ed80f6d3c55"
        },
        "date": 1785532920500,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 103394.06189007917,
            "unit": "iter/sec",
            "range": "stddev: 9.712916520923303e-7",
            "extra": "mean: 9.67173531748008 usec\nrounds: 8837"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 21543.732810648373,
            "unit": "iter/sec",
            "range": "stddev: 0.000012420795729614504",
            "extra": "mean: 46.41721138992831 usec\nrounds: 1036"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 97671.29134494564,
            "unit": "iter/sec",
            "range": "stddev: 0.0000028272990044933283",
            "extra": "mean: 10.238423043556379 usec\nrounds: 14989"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "27f3ac627d7d52a0cae18a47c376e81661f95b56",
          "message": "docs: add a table of contents to the README",
          "timestamp": "2026-08-03T17:29:36+02:00",
          "tree_id": "5c6b6e67ffd6c8894442eb8fba309dedfa9eb7bf",
          "url": "https://github.com/mangrisano/certinspect/commit/27f3ac627d7d52a0cae18a47c376e81661f95b56"
        },
        "date": 1785771008620,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 101630.69004861685,
            "unit": "iter/sec",
            "range": "stddev: 0.000001630481862602589",
            "extra": "mean: 9.839547478440146 usec\nrounds: 10331"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17325.81615545752,
            "unit": "iter/sec",
            "range": "stddev: 0.000006450521451100237",
            "extra": "mean: 57.71733874049024 usec\nrounds: 1048"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 95213.38165085262,
            "unit": "iter/sec",
            "range": "stddev: 0.000001657597095052072",
            "extra": "mean: 10.502725380209675 usec\nrounds: 21568"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "875fced61ac6070ff469894d711d8e0fbfe6acc9",
          "message": "chore(release): 1.13.0",
          "timestamp": "2026-08-03T19:19:34+02:00",
          "tree_id": "b2b82e15b46476b261ca9487b1062d2656c6d5ab",
          "url": "https://github.com/mangrisano/certinspect/commit/875fced61ac6070ff469894d711d8e0fbfe6acc9"
        },
        "date": 1785777608626,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 105131.9339112863,
            "unit": "iter/sec",
            "range": "stddev: 0.00000136267763356932",
            "extra": "mean: 9.511857746703607 usec\nrounds: 10172"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17522.648022534857,
            "unit": "iter/sec",
            "range": "stddev: 0.000007186231057379357",
            "extra": "mean: 57.06900000011175 usec\nrounds: 1057"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 97293.55760107706,
            "unit": "iter/sec",
            "range": "stddev: 0.000001647655519409758",
            "extra": "mean: 10.27817282723075 usec\nrounds: 22103"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "a7c2265d1072648c9ccc71e2b679f41e00d3904c",
          "message": "chore(release)!: 2.0.0",
          "timestamp": "2026-08-03T20:02:21+02:00",
          "tree_id": "76212e127a8b140ade4c03a118924db7df9fe023",
          "url": "https://github.com/mangrisano/certinspect/commit/a7c2265d1072648c9ccc71e2b679f41e00d3904c"
        },
        "date": 1785780171599,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 100410.20987257545,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014578305064450637",
            "extra": "mean: 9.959146597433069 usec\nrounds: 9052"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17382.592761544263,
            "unit": "iter/sec",
            "range": "stddev: 0.000006580271750973504",
            "extra": "mean: 57.52881711710539 usec\nrounds: 1110"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 99913.49868056687,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014437648843156396",
            "extra": "mean: 10.008657620899621 usec\nrounds: 21815"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "0aeed98fcb4900dc87508767dd61ab3ab860a13f",
          "message": "docs: update jq examples for schema-2 and vary duplicated examples\n\nThe default --json output is the schema-2 envelope, so the jq recipes now read the per-target objects from .results and use validity.days_to_expiry. Also diversify repeated example commands (revoked/broken hosts, --no-verify contrast) so each occurrence shows something distinct.",
          "timestamp": "2026-08-04T09:42:52+02:00",
          "tree_id": "5f8f61d0a243c51396fb457b394ac7e846fb789a",
          "url": "https://github.com/mangrisano/certinspect/commit/0aeed98fcb4900dc87508767dd61ab3ab860a13f"
        },
        "date": 1785829399751,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 96321.33883924133,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014820738948254477",
            "extra": "mean: 10.381915492983158 usec\nrounds: 11289"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 15793.776101550762,
            "unit": "iter/sec",
            "range": "stddev: 0.00001945223528769841",
            "extra": "mean: 63.31608056048178 usec\nrounds: 1142"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 97758.7694915483,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014033196421592565",
            "extra": "mean: 10.229261325619024 usec\nrounds: 24215"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "37e64a5e36824a5657704cc72eaee454fafd10e9",
          "message": "docs: use jpick instead of jq in the pipe examples\n\nReplace the jq one-liners with jpick equivalents; since jpick has no sort_by, let certinspect sort the fleet upstream with --sort expiry and jpick handle the iteration and interpolation.",
          "timestamp": "2026-08-04T09:45:40+02:00",
          "tree_id": "0b7401f1c4b424e0ba830bd0b8643cb39347f2f2",
          "url": "https://github.com/mangrisano/certinspect/commit/37e64a5e36824a5657704cc72eaee454fafd10e9"
        },
        "date": 1785829573874,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 102323.54323247836,
            "unit": "iter/sec",
            "range": "stddev: 0.0000015255973405529297",
            "extra": "mean: 9.772921933791983 usec\nrounds: 10363"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17461.63862369735,
            "unit": "iter/sec",
            "range": "stddev: 0.000007738811901017899",
            "extra": "mean: 57.26839396635382 usec\nrounds: 1127"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 99683.2027769346,
            "unit": "iter/sec",
            "range": "stddev: 0.000001411029310662694",
            "extra": "mean: 10.03178040173672 usec\nrounds: 22104"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "05e4929e543ad9afba67a513e7bc52749c2cd45f",
          "message": "chore(release): 2.1.0",
          "timestamp": "2026-08-15T00:17:06+02:00",
          "tree_id": "fd2b33399ced7fa01cbd9935fda924b9a55bc5cd",
          "url": "https://github.com/mangrisano/certinspect/commit/05e4929e543ad9afba67a513e7bc52749c2cd45f"
        },
        "date": 1786745853689,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 103472.53413700107,
            "unit": "iter/sec",
            "range": "stddev: 0.000001012096148285781",
            "extra": "mean: 9.6644003970751 usec\nrounds: 9066"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 22276.482054889857,
            "unit": "iter/sec",
            "range": "stddev: 0.000004316860572833115",
            "extra": "mean: 44.890391469172414 usec\nrounds: 1055"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 102982.1655111937,
            "unit": "iter/sec",
            "range": "stddev: 0.0000016016627533946533",
            "extra": "mean: 9.710419226825294 usec\nrounds: 21418"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "cb3a441dd49deaf110ff5adf957e6108ed41a39c",
          "message": "chore(release): 2.1.1",
          "timestamp": "2026-08-15T00:23:50+02:00",
          "tree_id": "5f4d9bab1117b2e16c399aff4d3a70050113acbd",
          "url": "https://github.com/mangrisano/certinspect/commit/cb3a441dd49deaf110ff5adf957e6108ed41a39c"
        },
        "date": 1786746247792,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 99217.06914472731,
            "unit": "iter/sec",
            "range": "stddev: 0.0000013193569956476263",
            "extra": "mean: 10.078910903337674 usec\nrounds: 10483"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17431.92693742963,
            "unit": "iter/sec",
            "range": "stddev: 0.000006747306094331279",
            "extra": "mean: 57.36600454954935 usec\nrounds: 1099"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 100696.44266873089,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014408292742310652",
            "extra": "mean: 9.930837410908147 usec\nrounds: 14878"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "8bca304deb6a2b1e18c06e5e59237dd971d01325",
          "message": "chore(deps): bump minimum dependency versions\n\nUpdate cryptography, pytest, ruff, and prometheus-client minimum\nversions to their latest releases.\n\nCo-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>",
          "timestamp": "2026-08-28T20:59:37+02:00",
          "tree_id": "54fbce37a253b829ca3dc8e67c179aef1bb1edc1",
          "url": "https://github.com/mangrisano/certinspect/commit/8bca304deb6a2b1e18c06e5e59237dd971d01325"
        },
        "date": 1787943600067,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 105811.16296868707,
            "unit": "iter/sec",
            "range": "stddev: 0.000001299448830742073",
            "extra": "mean: 9.450798686485776 usec\nrounds: 10963"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17462.806633871343,
            "unit": "iter/sec",
            "range": "stddev: 0.0000056783331850031636",
            "extra": "mean: 57.26456353587357 usec\nrounds: 1086"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 98301.20883101886,
            "unit": "iter/sec",
            "range": "stddev: 0.000001701096337568783",
            "extra": "mean: 10.17281488083238 usec\nrounds: 21894"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "c17ec5db5857ce4f92de1764fd19ab4d4fb88e15",
          "message": "chore(release): 2.2.0",
          "timestamp": "2026-09-03T17:47:06+02:00",
          "tree_id": "fe7909a4b169a5a806dc92ec26e268cd57957349",
          "url": "https://github.com/mangrisano/certinspect/commit/c17ec5db5857ce4f92de1764fd19ab4d4fb88e15"
        },
        "date": 1788450525685,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 156728.14950739697,
            "unit": "iter/sec",
            "range": "stddev: 8.734503091619499e-7",
            "extra": "mean: 6.380474746515167 usec\nrounds: 11246"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 35366.618257188115,
            "unit": "iter/sec",
            "range": "stddev: 0.0000028139078226838026",
            "extra": "mean: 28.27525076692212 usec\nrounds: 1304"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 159688.42321227342,
            "unit": "iter/sec",
            "range": "stddev: 0.0000010804726009350733",
            "extra": "mean: 6.262194715710246 usec\nrounds: 26721"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "d977a31edb2a4a9d2c1086ea50a80c6bbf26175d",
          "message": "docs: include --require-revocation-check in the exit code 9 table",
          "timestamp": "2026-09-20T15:11:51+02:00",
          "tree_id": "333e4a2f6671a613423378556755624b4d4c9d30",
          "url": "https://github.com/mangrisano/certinspect/commit/d977a31edb2a4a9d2c1086ea50a80c6bbf26175d"
        },
        "date": 1789909953009,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 104330.06291412101,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014093630196406085",
            "extra": "mean: 9.584964985817628 usec\nrounds: 11938"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17421.333846645255,
            "unit": "iter/sec",
            "range": "stddev: 0.000006790914467301712",
            "extra": "mean: 57.400886109106125 usec\nrounds: 1159"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 99268.2783210606,
            "unit": "iter/sec",
            "range": "stddev: 0.0000013983497442049638",
            "extra": "mean: 10.073711531147222 usec\nrounds: 23337"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "3555f3f69bd014455570eb836f35674e71a9cd9c",
          "message": "feat: config file, batch --file, concurrent discovery, state diffing, shell completion, Docker image\n\nBump to 2.3.0.\n\n- --config PATH loads default option values from a TOML file, auto-discovered\n  at ~/.config/certinspect/config.toml; explicit flags still override it.\n- --file is now repeatable to inspect several local certificates in one run.\n- --discover/--discover-only query multiple domains concurrently.\n- --state-file/--only-changed report only targets whose status changed since\n  the previous run, for low-noise recurring monitoring.\n- --print-completion {bash,zsh} generates a shell completion script from the\n  live argument parser.\n- Add a Dockerfile for a minimal container image.",
          "timestamp": "2026-09-20T16:27:44+02:00",
          "tree_id": "11a39d9bd265b36a94ba34ff8458cc2b14470eaa",
          "url": "https://github.com/mangrisano/certinspect/commit/3555f3f69bd014455570eb836f35674e71a9cd9c"
        },
        "date": 1789914581652,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 105187.59257279645,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014918615031549804",
            "extra": "mean: 9.506824669534451 usec\nrounds: 12485"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17376.992403362805,
            "unit": "iter/sec",
            "range": "stddev: 0.000008744486967331244",
            "extra": "mean: 57.54735783889043 usec\nrounds: 1129"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 101147.42551022363,
            "unit": "iter/sec",
            "range": "stddev: 0.0000018865381313607109",
            "extra": "mean: 9.88655909881684 usec\nrounds: 22547"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "c40f89cd157cd78617534fab828cf92cd32f7ae7",
          "message": "chore(release): 2.3.1",
          "timestamp": "2026-09-20T22:34:03+02:00",
          "tree_id": "8e1e711e76c2e6ef0446a284cc69b8e31d2ac97b",
          "url": "https://github.com/mangrisano/certinspect/commit/c40f89cd157cd78617534fab828cf92cd32f7ae7"
        },
        "date": 1789936470885,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 152789.15673803355,
            "unit": "iter/sec",
            "range": "stddev: 0.0000010105339942771957",
            "extra": "mean: 6.5449670732495875 usec\nrounds: 12786"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 34023.0406131164,
            "unit": "iter/sec",
            "range": "stddev: 0.0000029935087298204065",
            "extra": "mean: 29.391846877274244 usec\nrounds: 1489"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 160361.63692715668,
            "unit": "iter/sec",
            "range": "stddev: 8.682352046954522e-7",
            "extra": "mean: 6.235905414549017 usec\nrounds: 26706"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "1efffbc8112e1b5c3fcef8bc52eaaa5fd6f91005",
          "message": "chore(release): 2.3.2",
          "timestamp": "2026-09-20T22:59:00+02:00",
          "tree_id": "9d30db9e405a0e835ea2cefe0b40730f56379a6b",
          "url": "https://github.com/mangrisano/certinspect/commit/1efffbc8112e1b5c3fcef8bc52eaaa5fd6f91005"
        },
        "date": 1789937997175,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 103943.04351623805,
            "unit": "iter/sec",
            "range": "stddev: 0.0000012871950981683052",
            "extra": "mean: 9.620653447998945 usec\nrounds: 13718"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17533.725738703517,
            "unit": "iter/sec",
            "range": "stddev: 0.000006750203824245993",
            "extra": "mean: 57.03294410455072 usec\nrounds: 1145"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 99511.73688521457,
            "unit": "iter/sec",
            "range": "stddev: 0.0000020437022136226043",
            "extra": "mean: 10.049065882082697 usec\nrounds: 21751"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "67a535f8395e3422cee88b2724989cbb54e16d84",
          "message": "chore(release): 2.3.3",
          "timestamp": "2026-09-22T16:39:55+02:00",
          "tree_id": "4558f9571396c2755fadbbd021c883666b891dfd",
          "url": "https://github.com/mangrisano/certinspect/commit/67a535f8395e3422cee88b2724989cbb54e16d84"
        },
        "date": 1790088026670,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 183655.84576508502,
            "unit": "iter/sec",
            "range": "stddev: 7.252423029830585e-7",
            "extra": "mean: 5.444966893561909 usec\nrounds: 16160"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 40852.071969356984,
            "unit": "iter/sec",
            "range": "stddev: 0.0000016733610005622866",
            "extra": "mean: 24.47856257450288 usec\nrounds: 1678"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 187849.21844056854,
            "unit": "iter/sec",
            "range": "stddev: 5.524428522343959e-7",
            "extra": "mean: 5.3234184752085 usec\nrounds: 19583"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "a37cf78918f8c100c0803ee161d839c7b3efe333",
          "message": "chore(release): 2.4.0",
          "timestamp": "2026-09-25T19:06:10+02:00",
          "tree_id": "739f430af9ac451e13c2ac50047a79f723da9bb6",
          "url": "https://github.com/mangrisano/certinspect/commit/a37cf78918f8c100c0803ee161d839c7b3efe333"
        },
        "date": 1790355988670,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 103494.17210945048,
            "unit": "iter/sec",
            "range": "stddev: 0.0000016253351339987232",
            "extra": "mean: 9.662379819246711 usec\nrounds: 12943"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17081.922143152526,
            "unit": "iter/sec",
            "range": "stddev: 0.000006245707685292114",
            "extra": "mean: 58.5414212533957 usec\nrounds: 1308"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 100683.55207524964,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014082935467268765",
            "extra": "mean: 9.932108863745814 usec\nrounds: 25463"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "3ec9f6f461dbabfca33aac030674fbbe4bb16a22",
          "message": "chore(release): 2.4.1",
          "timestamp": "2026-09-25T19:56:01+02:00",
          "tree_id": "9ee0565c338c7099371692a72530536d74f11bb9",
          "url": "https://github.com/mangrisano/certinspect/commit/3ec9f6f461dbabfca33aac030674fbbe4bb16a22"
        },
        "date": 1790359013811,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 102130.69580979145,
            "unit": "iter/sec",
            "range": "stddev: 0.0000024490970705953445",
            "extra": "mean: 9.791375570988015 usec\nrounds: 10725"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 17279.76128641278,
            "unit": "iter/sec",
            "range": "stddev: 0.000006414314803237773",
            "extra": "mean: 57.87116982838809 usec\nrounds: 1107"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 99217.42225387385,
            "unit": "iter/sec",
            "range": "stddev: 0.0000017020724832271317",
            "extra": "mean: 10.07887503306866 usec\nrounds: 22654"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "68b6195a270fba881b7ffa9d3c7512042cc46103",
          "message": "chore(release): 2.4.2",
          "timestamp": "2026-09-25T21:27:01+02:00",
          "tree_id": "45704dac0f14a0b6f23977448f5307736d04fb35",
          "url": "https://github.com/mangrisano/certinspect/commit/68b6195a270fba881b7ffa9d3c7512042cc46103"
        },
        "date": 1790364441078,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_load_certificate",
            "value": 102611.1582214283,
            "unit": "iter/sec",
            "range": "stddev: 0.0000019480308612597904",
            "extra": "mean: 9.745528822918695 usec\nrounds: 14485"
          },
          {
            "name": "benchmarks/bench_perf.py::test_analyze",
            "value": 16973.0592144478,
            "unit": "iter/sec",
            "range": "stddev: 0.00000601207550401888",
            "extra": "mean: 58.916898089224865 usec\nrounds: 1099"
          },
          {
            "name": "benchmarks/bench_perf.py::test_format_json",
            "value": 100470.26412157645,
            "unit": "iter/sec",
            "range": "stddev: 0.0000017408394466096052",
            "extra": "mean: 9.953193701072848 usec\nrounds: 15209"
          }
        ]
      }
    ]
  }
}