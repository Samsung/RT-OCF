# RT-OCF
The RT-OCF project is to develop an open source software framework which is a light-weight device-to-device (D2D) framework based on Open Connectivity Foundation (OCF) specification for IoT devices. RT-OCF targets TizenRT RTOS and provides functionalities such as device discovery, create/read/update/delete operations of device resources, resource observation, and so on. All target functionalities of RT-OCF are not yet completed. For example, provisioning to cloud considering sercurity together is underdeveloped.

## Setup Preparation

To run `RT-OCF`, you need to install the package below.

```sh
# For TizenRT test
$ sudo pip install pyserial

## Setup development environment

1. Clone Tizen RT first and move to external directory.

```sh
$ git clone https://github.com/Samsung/TizenRT.git
$ cd external
```

2. Clone RT-OCF.

```sh
$ git clone https://github.com/Samsung/RT-OCF.git
```

3. Work within `external/RT-OCF`.

## How to Setup

For Setup RT-OCF options

```sh
os/linux$ make menuconfig
```

## How to build

### Linux

For Building RT-OCF with linux

**python script(recommended)**

```sh
$ ./tools/build.py linux -h
usage: build.py linux [-h] [--rebuild] [--ci]

Linux Build

optional arguments:
  -h, --help  show this help message and exit
  --rebuild   True, Build after clean
  --ci        True, if it is ci build.
```

**shell script**

```sh
$ tools/build_linux.sh
```

### TizenRT

For Building RT-OCF with TizenRT

**python script(recommended)**

```sh
$ ./tools/build.py tizenrt -h
usage: build.py tizenrt [-h] [--rebuild] [--config CONFIG] [--with-flash]
                        [--ci]

Tizen RT Build

optional arguments:
  -h, --help       show this help message and exit
  --rebuild        True, Build after clean
  --config CONFIG  Select the config you want to use for the TizenRT build.
  --with-flash     True, if you want to flash binary after building
  --ci             True, if it is ci build.
```

**shell script**

```sh
$ tools/build.py tizenrt

# artik053/zeroroot config
# If you want to build with RT-OCF, run this script.
$ tools/build_tizenrt_zeroroot.sh

# build TizenRT with specify config name
$ tools/build_tizenrt_with_configure.sh ${CONFIG_NAME}

# build TizenRT without configuration
# Use this script if you want to build the old configuration.
$ tools/build_tizenrt.sh ${CONFIG_NAME}
```

## How to test

### Linux

For Testing RT-OCF with linux

**python script(recommended)**

```sh
$ ./tools/test.py linux -h
usage: test.py linux [-h] [--rebuild] [--skip-build] [--cov] [--ci] [-v]
                     [-g GROUP] [-n NAME] [-c COUNT]

Linux Test

optional arguments:
  -h, --help            show this help message and exit
  --rebuild             True, Build after clean
  --skip-build          True, if you want to execute only test
  --cov                 True, If you want to calculate test coverage.
  --ci                  True, if it is ci build.
  -v, --verbose         Print test name before each test run
  -g GROUP, --group GROUP
                        Select a test group whose name contains the specified
                        string
  -n NAME, --name NAME  Select a test case whose name contains the specified
                        string
  -c COUNT, --count COUNT
                        Repeat the test for the specified number of times
```

**shell script**

```sh
$ tools/test_linux.sh
# Run specific test group
$ tools/test_linux.sh -g test_mem
# Run specific test name
$ tools/test_linux.sh -n getMemInfo_alloc_int_free_one
# Generate coverage report
$ tools/coverage_linux.sh
```

### TizenRT

For Testing RT-OCF with TizenRT

**python script**

```sh
$ ./tools/test.py tizenrt -h
usage: test.py tizenrt [-h] [--skip-build] [--rebuild] [--ci]

Tizen RT Test

optional arguments:
  -h, --help    show this help message and exit
  --skip-build  True, if you want to execute only test
  --rebuild     True, Build after clean
  --ci          True, if it is ci build.
```

## Flash to target board

Use to install binaries on board.

```sh
$ ./tools/flash.py  -h
usage: flash.py [-h] [--all]

Use to install binaries on board.

optional arguments:
  -h, --help  show this help message and exit
  --all       True, if you want to flash all.
```

