#!/usr/bin/env python

import yaml

data={
    "candlepin.conf": {
        "auth_cloud_enable": "true",
    }
}

f=open('server/custom.yaml','w')
f.write(yaml.dump(data))
f.close()