# pyawvs
pyawvs是python3实现的awvs 12 api和shell管理脚本，只实现了部分核心功能。
## usage
```
usage: pyawvs.py [-h] [-c CONFIG] [-i] [-r] [--awvs-api AWVS_API]
                 [--awvs-key AWVS_KEY] [--awvs-proxy AWVS_PROXY]
                 [--time-out TIME_OUT] [--retry RETRY] [-t TARGET]
                 [--target-proxy TARGET_PROXY]
                 [--target-proxy-auth TARGET_PROXY_AUTH] [-a] [-d]
                 [--delete-all-targets] [-s] [--scan-after SCAN_AFTER]
                 [--scan-type SCAN_TYPE] [--scan-report SCAN_REPORT]

pyawvs

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        -c config.json | awvs config file
  -i, --info            -i | awvs information
  -r, --reports         -r | download reports
  --awvs-api AWVS_API   --awvs-api https://127.0.0.1/ | awvs web url
  --awvs-key AWVS_KEY   --awvs-key 1986ad8c0 | awvs api key
  --awvs-proxy AWVS_PROXY
                        --awvs-proxy 127.0.0.1:8080 | pyawvs proxy
  --time-out TIME_OUT   --time-out 5 | awvs time-out
  --retry RETRY         --retry 3 | awvs time-out retry count
  -t TARGET, --target TARGET
                        -t t.txt or -t url | target file or single url
  --target-proxy TARGET_PROXY
                        --target-proxy 127.0.0.1:8080 | target proxy
  --target-proxy-auth TARGET_PROXY_AUTH
                        --target-proxy admin:123456 | target proxy auth
  -a, --add             -a | add target
  -d, --delete          -d | delete target
  --delete-all-targets  --delete-all-targets | delete all targets
  -s, --scan            -s | add scan
  --scan-after SCAN_AFTER
                        --scan-after 5 | scan after some minutes
  --scan-type SCAN_TYPE
                        --scan-type FullScan | view scan types by -i
  --scan-report SCAN_REPORT
                        --scan-report AffectedItems | view report templates by
                        -i

```