#!/bin/bash

###### #Please specify below ######
SVACE_DIR=svace_dir_script
CLEAN_CMD=""

# For svace manager
USER=jaehong.jo
PASS=svace
MODULE=17_RT_OCF_ALL

# For error check
msg_error()
{
    echo ---------------------------------------------------------------------
    echo "Fail to Build, Check Last Step. [$_STEP]"
    echo ---------------------------------------------------------------------
    exit 2
}

error_check()
{
    if [ $? != 0 ]
    then
       msg_error
    fi
}


# For Platform
echo "-------------------------- Start Linux Svace --------------------------"
BUILD_CMD="./build.py linux --rebuild"

# svace init
rm -rf $SVACE_DIR
svace init --bare $SVACE_DIR

# settings svace checkers
cp warn-settings.130.txt $SVACE_DIR/warn-settings.txt


_STEP=CLEAN
#echo $CLEAN_CMD
#rm -rf out
#$CLEAN_CMD

_STEP=BUILD
SVACE_BUILD_CMD="svace build --svace-dir $SVACE_DIR --clang-opts=-Xanalyzer;-analyzer-checker=crc $BUILD_CMD"
echo $SVACE_BUILD_CMD
$SVACE_BUILD_CMD
error_check


_STEP=ANALYZE
echo svace analyze --svace-dir $SVACE_DIR
svace analyze --svace-dir $SVACE_DIR
error_check


_STEP=COMMIT
echo "svace upload --svace-dir $SVACE_DIR --host 10.113.139.45:8081 --module $MODULE --user $USER --pass $PASS"
svace upload --svace-dir $SVACE_DIR --host 10.113.139.45:8081 --module $MODULE --user $USER --pass $PASS
error_check

# svace terminate
rm -rf $SVACE_DIR
echo "-------------------------- Succeded to Svace --------------------------"
