REPOSITORY_URL = 'https://github.com/Praqma/codesonar-plugin.git'
MAIN_BRANCH = 'master'
REMOTE_NAME = 'origin'
NUM_OF_BUILDS_TO_KEEP = 100
GITHUB_PRAQMA_CREDENTIALS = '100247a2-70f4-4a4e-a9f6-266d139da9db'

DOCKERHOST1_SLAVE_LABEL = 'dockerhost1'
JENKINSUBUNTU_LABEL = 'jenkinsubuntu'

UNIT_TESTS_JOB_NAME = '1_unit-tests_codesonar'
INTEGRATION_TESTS_JOB_NAME = '2_integration-tests_codesonar'
ANALYSIS_JOB_NAME = '3_analysis_codesonar'
PAC_JOB_NAME = '4_pac_codesonar'
PUSH_TO_JENKINSCI_JOB_NAME = '5_push_to_jenkinsci_codesonar'
RELEASE_JOB_NAME = '6_release_codesonar'
SYNC_JOB_NAME = '7_sync_jenkinsci_codesonar'

job(UNIT_TESTS_JOB_NAME) {

    logRotator {
        numToKeep(NUM_OF_BUILDS_TO_KEEP)
    }

    label(DOCKERHOST1_SLAVE_LABEL)

    properties {
        ownership {
            primaryOwnerId('and')
            coOwnerIds('man')
        }
    }

    scm {
        git {
            remote {
                name(REMOTE_NAME)
                url(REPOSITORY_URL)
            }
            branch(MAIN_BRANCH)
            extensions {}
        }
    }

    triggers {
        scm("* * * * *")
    }

    authorization {
        permission('hudson.model.Item.Read', 'anonymous')
    }

    steps {
        maven {
            goals('clean compile test')
            mavenInstallation('Latest')
        }
    }

    wrappers {
        buildName('${BUILD_NUMBER}#${GIT_REVISION,length=8}(${GIT_BRANCH})')
    }

    publishers {
        archiveJunit('target/surefire-reports/*.xml')
        downstream(INTEGRATION_TESTS_JOB_NAME, 'SUCCESS')
        mailer('man@praqma.net', false, false)
    }
}

job(INTEGRATION_TESTS_JOB_NAME) {

    logRotator {
        numToKeep(NUM_OF_BUILDS_TO_KEEP)
    }

    label(DOCKERHOST1_SLAVE_LABEL)

    properties {
        ownership {
            primaryOwnerId('and')
            coOwnerIds('man')
        }
    }

    scm {
        git {
            remote {
                name(REMOTE_NAME)
                url(REPOSITORY_URL)
            }
            branch(MAIN_BRANCH)
            extensions {}
        }
    }

    authorization {
        permission('hudson.model.Item.Read', 'anonymous')
    }

    steps {
        maven {
            goals('clean integration-test')
            mavenInstallation('Latest')
        }
    }

    wrappers {
        buildName('${BUILD_NUMBER}#${GIT_REVISION,length=8}(${GIT_BRANCH})')
    }

    publishers {
        archiveJunit('target/surefire-reports/*.xml')
        downstream(ANALYSIS_JOB_NAME, 'SUCCESS')
        mailer('man@praqma.net', false, false)
    }
}

job(ANALYSIS_JOB_NAME) {

    logRotator {
        numToKeep(NUM_OF_BUILDS_TO_KEEP)
    }

    label(DOCKERHOST1_SLAVE_LABEL)

    properties {
        ownership {
            primaryOwnerId('and')
            coOwnerIds('man')
        }
    }

    scm {
        git {
            remote {
                name(REMOTE_NAME)
                url(REPOSITORY_URL)
            }
            branch(MAIN_BRANCH)
            extensions {}
        }
    }

    authorization {
        permission('hudson.model.Item.Read', 'anonymous')
    }

    steps {
        maven {
            goals('clean package findbugs:check')
            mavenInstallation('Latest')
        }
    }

    wrappers {
        buildName('${BUILD_NUMBER}#${GIT_REVISION,length=8}(${GIT_BRANCH})')
    }
	
    publishers {
        archiveArtifacts('target/codesonar.*')

        findbugs('target/findbugsXml.xml', false) {
            healthLimits(3, 20)
            thresholdLimit('high')
            defaultEncoding('UTF-8')
            canRunOnFailed(true)
            useStableBuildAsReference(true)
            useDeltaValues(true)
            computeNew(true)
            shouldDetectModules(true)
            thresholds(
                    unstableTotal: [all: 1, high: 2, normal: 3, low: 4],
                    failedTotal: [all: 5, high: 6, normal: 7, low: 8],
                    unstableNew: [all: 9, high: 10, normal: 11, low: 12],
                    failedNew: [all: 13, high: 14, normal: 15, low: 16]
            )
        }

        analysisCollector {
            findbugs()
        }

        downstream(PAC_JOB_NAME, 'SUCCESS')
        mailer('and@praqma.net', false, false)
    }
}

job(PAC_JOB_NAME) {
    configure { 
		it / 'buildWrappers' / 'EnvInjectPasswordWrapper' {
          injectGlobalPasswords('true')
          maskPasswordParameters('true')
		}
    }
	
    logRotator {
        numToKeep(NUM_OF_BUILDS_TO_KEEP)
    }

    label(DOCKERHOST1_SLAVE_LABEL)

    properties {
        ownership {
            primaryOwnerId('man')
        }
    }

    scm {
        git {
            remote {
                name(REMOTE_NAME)
                url(REPOSITORY_URL)
            }
            branch(MAIN_BRANCH)
            extensions {
				
			}
        }
    }
	
    authorization {
        permission('hudson.model.Item.Read', 'anonymous')
    }

    steps {
        shell('docker run --rm -v \$(pwd):/data praqma/pac:snapshot from-latest-tag "*" --settings=/data/pac/pac_settings.yml -c ReleasePraqma \$secret_password_pac jira')
    }

    wrappers {
        buildName('${BUILD_NUMBER}#${GIT_REVISION,length=8}(${GIT_BRANCH})')
    }


    publishers {
        archiveArtifacts('default-generated.*')
		
		publishHtml{ 
			report('.') {
				reportFiles("default-generated.html")
				reportName('Autogenerated changelog')
			} 
		}
			
        downstream(PUSH_TO_JENKINSCI_JOB_NAME, 'SUCCESS')
        mailer('man@praqma.net', false, false)
    }
}

job(PUSH_TO_JENKINSCI_JOB_NAME) {

    logRotator {
        numToKeep(NUM_OF_BUILDS_TO_KEEP)
    }

    label(JENKINSUBUNTU_LABEL)

    properties {
        ownership {
            primaryOwnerId('man')
        }
    }

    scm {
        git {
            remote {
                name(REMOTE_NAME)
                url(REPOSITORY_URL)
            }
            branch(MAIN_BRANCH)
            extensions {
                wipeOutWorkspace()
            }
        }
    }

    authorization {
        permission('hudson.model.Item.Read', 'anonymous')
    }

    steps {
        shell('''git checkout master
                |git fetch --tags git@github.com:Praqma/codesonar-plugin.git

                |# push for JenkinsCI github repo:

                |git push git@github.com:jenkinsci/codesonar-plugin.git ${BRANCH}
                |git push git@github.com:jenkinsci/codesonar-plugin.git --tags'''.stripMargin())
    }

    wrappers {
        buildName('${BUILD_NUMBER}#${GIT_REVISION,length=8}(${GIT_BRANCH})')
    }

    publishers {
        buildPipelineTrigger(RELEASE_JOB_NAME) {
            parameters {
                gitRevision()
            }
        }
        mailer('man@praqma.net', false, false)
    }
}

job(RELEASE_JOB_NAME) {

    logRotator {
        numToKeep(NUM_OF_BUILDS_TO_KEEP)
    }

    label(JENKINSUBUNTU_LABEL)

    properties {
        ownership {
            primaryOwnerId('man')
        }
    }

    scm {
        git {
            remote {
                name(REMOTE_NAME)
                url(REPOSITORY_URL)
            }
            branch(MAIN_BRANCH)
            extensions {
                wipeOutWorkspace()
                localBranch(MAIN_BRANCH)
            }
        }
    }

    authorization {
        permission('hudson.model.Item.Read', 'anonymous')
    }

    steps {
        maven {
            goals('release:clean release:prepare release:perform -B')
            mavenInstallation('Latest')
        }
    }

    wrappers {
        buildName('${BUILD_NUMBER}#${GIT_REVISION,length=8}(${GIT_BRANCH})')
    }

    publishers {
        downstream(SYNC_JOB_NAME, 'SUCCESS')
        mailer('man@praqma.net', false, false)
    }
}

job(SYNC_JOB_NAME) {

    logRotator {
        numToKeep(NUM_OF_BUILDS_TO_KEEP)
    }

    label(JENKINSUBUNTU_LABEL)

    properties {
        ownership {
            primaryOwnerId('man')
        }
    }

    scm {
        git {
            remote {
                name(REMOTE_NAME)
                url(REPOSITORY_URL)
            }
            branch(MAIN_BRANCH)
            extensions {
                wipeOutWorkspace()
            }
        }
    }

    authorization {
        permission('hudson.model.Item.Read', 'anonymous')
    }

    steps {
        shell('''git checkout master
                |git fetch --tags git@github.com:Praqma/codesonar-plugin.git

                |# push for JenkinsCI github repo:

                |git push git@github.com:jenkinsci/codesonar-plugin.git ${BRANCH}
                |git push git@github.com:jenkinsci/codesonar-plugin.git --tags'''.stripMargin())
    }

    wrappers {
        buildName('${BUILD_NUMBER}#${GIT_REVISION,length=8}(${GIT_BRANCH})')
    }

    publishers {
        mailer('man@praqma.net', false, false)
    }
}
