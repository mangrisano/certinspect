window.BENCHMARK_DATA = {
  "lastUpdate": 1785532921262,
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
      }
    ]
  }
}