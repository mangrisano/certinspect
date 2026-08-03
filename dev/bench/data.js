window.BENCHMARK_DATA = {
  "lastUpdate": 1785771009350,
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
      }
    ]
  }
}