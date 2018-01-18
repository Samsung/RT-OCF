pipeline {
    agent any
    environment {
        TIZENRT_ROOT = "TizenRT"
        TIZENRT_IOTIVITYRT_ROOT = "TizenRT/external/iotivity-rt"
        TIZENRT_IOTIVITYRT_TOOLS = "TizenRT/external/iotivity-rt/tools"
        TIZENRT_IOTIVITYRT_LINUX_ROOT = "TizenRT/external/iotivity-rt/os/linux"

        IOTIVITYRT_ROOT = "iotivity-rt"
        IOTIVITYRT_TOOLS = "iotivity-rt/tools"
        IOTIVITYRT_LINUX_ROOT = "iotivity-rt/os/linux"
    } 
    stages {
        stage('Prerequisite') {
            steps {
                sh 'pwd'
                sh 'rm -rf ${TIZENRT_ROOT} ${IOTIVITYRT_ROOT}'
                sh "mkdir -p ${TIZENRT_ROOT} ${IOTIVITYRT_ROOT}"
                
                sh "mkdir -p ${IOTIVITYRT_ROOT}"
                sh "mv * ${IOTIVITYRT_ROOT} || true"

                dir("${TIZENRT_ROOT}") {
                    git([url: 'git@github.sec.samsung.net:RS-ZeroRoot/TizenRT.git', branch: 'master', credentialsId: 'd541b912-91b6-421a-850e-fbc4e32aaabd'])
                }

                dir("${IOTIVITYRT_LINUX_ROOT}") {
                    sh "mv default_config .config"
                }

                sh "cp -r ${IOTIVITYRT_ROOT} ${TIZENRT_IOTIVITYRT_ROOT}"
                
                setBuildStatus("1/coding/lint", "" , "PENDING")
                setBuildStatus("2/build-status/linux", "", "PENDING")
                setBuildStatus("3/build-status/tizen-rt", "", "PENDING")
                setBuildStatus("4/test/linux", "", "PENDING")
                setBuildStatus("5/test/tizenrt", "", "PENDING")
                setBuildStatus("6/coverage/linux", "", "PENDING")
                setBuildStatus("7/memory/leak", "", "PENDING")
                setBuildStatus("8/memory/peak", "", "PENDING")
            }
        }
        stage('Coding rule') {
            steps {
                dir("${IOTIVITYRT_ROOT}") {
                    codingRule()
                }
            }   
        }
        stage('Build') {
            steps {
                parallel(
                    Linux: {
                        dir("${IOTIVITYRT_TOOLS}") {
                            buildLinux()
                        }
                    },
                    TizenRT: {
                        dir("${TIZENRT_IOTIVITYRT_TOOLS}") {
                            buildTizenRT()
                        }
                    }
                )
            }
        }

        stage('Test/Coverage') {
            steps {
                 parallel(
                     Linux: {
                        dir("${IOTIVITYRT_TOOLS}") {
                            linux_test_and_coverage()
                        }
                        dir("${IOTIVITYRT_LINUX_ROOT}"){
                            publishHTML target: [
                                allowMissing: false,
                                alwaysLinkToLastBuild: false,
                                keepAll: true,
                                reportDir: 'covhtml',
                                reportFiles: 'index.html',
                                reportName: 'GCov Report'
                            ]
                        }
                     },
                     TizenRT: {
                         dir("${TIZENRT_IOTIVITYRT_TOOLS}") {
                             testTizenRT()
                         }
                     }
                 )
            }
        }

        stage('Memory Leak/Peak') {
            steps{
                dir("${IOTIVITYRT_TOOLS}") {
                    memory()
                }
            } 
        }
        
        stage('Metric - Lizard') {
            steps {
                dir("${IOTIVITYRT_ROOT}") {
                    metric()
                }
            }
        }
    }
}

void codingRule(){
    TEST_RESULT = "FAILURE"
    try {
        timeout(time: 10, unit: 'MINUTES'){
            sh "tools/lint.sh --ci"
            TEST_RESULT = "SUCCESS"
        }
    } catch(err) {
        TEST_RESULT = "FAILURE"
        throw err
    } finally {
        setBuildStatus("1/coding/lint", readFile("ci_lint.txt").trim(), TEST_RESULT)
    }
}

void buildLinux(){
    TEST_RESULT = "FAILURE"
    try {
        timeout(time: 10, unit: 'MINUTES'){
            sh 'python -u ./build.py linux --ci --rebuild'
            TEST_RESULT = "SUCCESS"
        }
    } catch(err) {
        TEST_RESULT = "FAILURE"
        throw err
    } finally {
        setBuildStatus("2/build-status/linux", readFile("ci_linux_build.txt").trim(), TEST_RESULT)
    }
}

void buildTizenRT(){
    TEST_RESULT = "FAILURE"
    try {
        timeout(time: 10, unit: 'MINUTES'){
            sh 'python -u ./build.py tizenrt --ci --rebuild --config artik053/zeroroot_unittest'
            TEST_RESULT = "SUCCESS"
        }
    } catch(err) {
        TEST_RESULT = "FAILURE"
        throw err
    } finally {
        setBuildStatus("3/build-status/tizen-rt", readFile("ci_tizenrt_build.txt").trim(), TEST_RESULT)
    }
}

void linux_test_and_coverage(){
    TEST_RESULT = "FAILURE"
    try {
        timeout(time: 10, unit: 'MINUTES'){
            sh 'NOCOLOR=1 python -u ./test.py linux --ci --cov'
            TEST_RESULT = "SUCCESS"
        }
    } catch(err) {
        TEST_RESULT = "FAILURE"
        throw err
    } finally {
        setBuildStatus("4/test/linux", readFile("ci_linux_test.txt").trim(), TEST_RESULT)
        setBuildStatus("6/coverage/linux", readFile("ci_linux_coverage.txt").trim(), TEST_RESULT)
    }
}

void testTizenRT(){
    TEST_RESULT = "FAILURE"
    try {
        timeout(time: 10, unit: 'MINUTES'){
            sh 'python -u ./test.py tizenrt --ci'
            TEST_RESULT = "SUCCESS"
        }
    } catch(err) {
        TEST_RESULT = "FAILURE"
        throw err
    } finally {
        setBuildStatus("5/test/tizenrt", readFile("ci_tizenrt_test.txt").trim(), TEST_RESULT)
    }
}

void memory(){
    TEST_RESULT = "FAILURE"
    try {
        timeout(time: 10, unit: 'MINUTES'){
            sh "python -u ./memory.py --ci"
            TEST_RESULT = "SUCCESS"
        }
    } catch(err) {
        TEST_RESULT = "FAILURE"
        throw err
    } finally {
        setBuildStatus("7/memory/leak", readFile("ci_linux_leak.txt").trim(), TEST_RESULT)
        setBuildStatus("8/memory/peak", readFile("ci_linux_peak.txt").trim(), TEST_RESULT)
    }
}

void metric(){
    try{
        sh 'lizard . -x"./extlibs/*" -x"./*/test/*" -x"./os/*" -x"./tools/*" || :'
    } catch(err) {

    }
}

void setBuildStatus(String context, String message, String state) {
    step([
        $class: "GitHubCommitStatusSetter",
        reposSource: [$class: "ManuallyEnteredRepositorySource", url: "https://github.sec.samsung.net/RS-ZEROROOT/iotivity-rt"],
        contextSource: [$class: "ManuallyEnteredCommitContextSource", context: context],
        errorHandlers: [[$class: "ChangingBuildStatusErrorHandler", result: "UNSTABLE"]],
        statusResultSource: [ $class: "ConditionalStatusResultSource", results: [[$class: "AnyBuildResult", message: message, state: state]] ]
    ]);
}       
