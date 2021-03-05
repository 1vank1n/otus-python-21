# HW1 — LogAnalyzer

## Requirements

Python >= 3.6

## Quickstart

1. Clone
2. Put logs files to `./log/` folder
3. Run script `python log_analyzer.py`

## Usage

* For help run script with `-h` flag. Ex.: `python log_analyzer.py -h`
* For load with custom config use `--config=filename.json`
* For testing run `python tests.py`

## Examples

1. Simple custom config with different `REPORT_SIZE`: `python log_analyzer.py --config=config.json`
1. Save logs to file `log_analyzer.log`: `python log_analyzer.py --config=config_logfile.json`
1. Set `TERMINATED_PERCENT` errors in parsing: `python log_analyzer.py --config=config_terminated.json`
