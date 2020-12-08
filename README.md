# Residual Trust: Expired Domains

## Andy Liang, Ivan Lin, Johnny So

### Acknowledgments

This work is a continuation of Najmeh Miramirkhani's last project as a PhD student with Professors Nick Nikiforakis and Mike Ferdman at Stony Brook University.

### Description

We started off with the `ingestion/` folder to begin centralizing container logs into Elasticsearch. The container logs were shipped periodically to a central NAS; we mounted this NAS onto an instance and ran `ingestion/ingester.py`, which ingests one container's logs at a time.

While the ingestion was happening, we used `stats/` to download snapshots of the data to do some offline processing in an easy format (i.e. using `pandas`).

After the cluster had ingested a sizable portion of the logs, we switched over to `bot-tagging` to execute the pipeline on Elasticsearch. This pipeline creates a new index called `ips-{service}` where the documents are of the form `{"ip": ip, bot_filter_tags: [tag-1, tag-2, ...]}`. This makes it easy to do queries on the IPs for a specific service.

The `ssh` pipeline is not done yet from time constraints but will be very similar to the other two credentials-based services `ftp/telnet`. We do not actually allow them to connect, so although `cowrie` (the SSH honeypot service) has verbose logging, there will probably not be much more logging granularity there.

We obtained access to Farsight's DNSDB2 from a PragSec Lab member and used it to query some of the domains in our data. We have, however, redacted the API key.

### Main Dependencies
* `elasticsearch`
* `elasticsearch-dsl`
* `pandas`
* `matplotlib`
* `seaborn`
* `tldextract`

### Directory Structure
* `ansible/`
  * move `ansible.cfg, ssh.cfg, hosts` into your Ansible directory (`/etc/ansible` in Linux)
  * setup your SSH configs to use the correct keys
  * test your connection with `ansible all -m ping`
* `bot-tagging/` - main bot-tagging pipeline for the different services
* `data/` - data directory
* `domain_lookups/` - using a passive DNS database to lookup specific domains
* `ingestion/` - centralizing data from containers to Elasticsearch cluster
* `stats/` - old bot-tagging pipeline that downloaded a snapshot and tagged those offline