window.BENCHMARK_DATA = {
  "lastUpdate": 1787943600699,
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
      }
    ]
  }
}