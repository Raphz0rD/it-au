import groovy.json.JsonSlurperClassic

@NonCPS
def jsonParse(def json) {
    new groovy.json.JsonSlurperClassic().parseText(json)
}

node {
    
//Integration pipeline

def DEPARTMENT = sh(script: "echo ${JOB_NAME} | cut -d / -f 1", returnStdout: true).trim()
def DOMAIN = sh(script: "echo ${JOB_NAME} | cut -d / -f 2", returnStdout: true).trim()
def PROJECT = sh(script: "echo ${JOB_NAME} | cut -d / -f 3", returnStdout: true).trim()
def ENVIRONMENT = sh(script: "echo ${JOB_NAME} | cut -d / -f 4", returnStdout: true).trim()
def BUILD_USER = ""
def USER_EMAIL = ""

if (env.gitlabUserName) {
    BUILD_USER = "${gitlabUserName}"
    if (env.gitlabUserEmail) {
    USER_EMAIL = "${gitlabUserEmail}"
    } else {
        echo "Usuario sem email cadastrado no repositorio"
        USER_EMAIL = "jenkins@services.crednovo.com.br"
    }
    echo "Gitlab Push User: ${BUILD_USER}"
    echo "Gitlab User email: ${USER_EMAIL}"
} else {

    wrap([$class: 'BuildUser']) {
        BUILD_USER = env.BUILD_USER_ID
        USER_EMAIL = env.BUILD_USER_EMAIL
    }
    echo "Jenkins User: ${BUILD_USER}"
    echo "Jenkins User Email: ${USER_EMAIL}"   
}

//Tests enabled? set to true / false
def TESTS= "false"
def APM= "true"

try {

    stage("Setou variaveis e Construiu"){

        switch (DOMAIN) {
            case "backend":
                //Set Cluster Name
                def CLUSTER_NAME = ""
                //Currently Accepted values: node / java
                def PROJECT_LANG = ""
                //Set for NodeJS Only: Available versions = 8 / 10 / 12 / 14
                def NODE_VERSION = ""
                //Number of JS files in this project
                def jsFiles_NUMBER = ""
                //Name of file #1
                def jsFile_1 = ""
                //Name of file #2
                def jsFile_2 = ""
                //BUILD JOB
                build job: 'cd', propagate: false, wait: false, parameters: [
                                string(name: 'CLUSTER_NAME', value: "${CLUSTER_NAME}"),
                                string(name: 'PROJECT_LANG', value: "${PROJECT_LANG}"),
                                string(name: 'NODE_VERSION', value: "${NODE_VERSION}"),
                                string(name: 'TESTS', value: "${TESTS}"),
                                string(name: 'APM', value: "${APM}"),
                                string(name: 'BUILD_USER', value: "${BUILD_USER}"),
                                string(name: 'USER_EMAIL', value: "${USER_EMAIL}"),
                                string(name: 'jsFiles_NUMBER', value: "${jsFiles_NUMBER}"),
                                string(name: 'jsFile_1', value: "${jsFile_1}"),
                                string(name: 'jsFile_2', value: "${jsFile_2}")
                                ]
                break;
            case "frontend":
                def S3_URI = ""
                def CLOUD_FRONT_ID = ""
                def BUILD_COMMAND = ""
                def CODE_FOLDER = ""
                if (ENVIRONMENT == "development") {
                    //Set these Variables accordingly to the project configuration
                    // Use model: s3://<bucketName>/<folderPath>
                    S3_URI = "s3://uri.com.br/"
                    // Just the ID of the CDN Distribution
                    CLOUD_FRONT_ID = ""
                    BUILD_COMMAND = "sudo ng build --output-hashing all"
                } else if (ENVIRONMENT == "homolog") {
                    //Set these Variables accordingly to the project configuration
                    // Use model: s3://<bucketName>/<folderPath>
                    S3_URI = "s3://uri.com.br/"
                    // Just the ID of the CDN Distribution
                    CLOUD_FRONT_ID = ""
                    BUILD_COMMAND = "sudo ng build --prod --configuration=hml --output-hashing all"
                } else if (ENVIRONMENT == "production") {
                    //Set these Variables accordingly to the project configuration
                    // Use model: s3://<bucketName>/<folderPath>
                    S3_URI = "s3://uri.com.br/"
                    // Just the ID of the CDN Distribution
                    CLOUD_FRONT_ID = ""
                    BUILD_COMMAND = "sudo ng build --prod --configuration=prod --output-hashing all"
                } else {
                    echo "Nao foi possivel obter o ambiente para o deploy"
                }
                //BUILD JOB
                build job: 'cd', propagate: false, wait: false, parameters: [
                                string(name: 'S3_URI', value: "${S3_URI}"),
                                string(name: 'CLOUD_FRONT_ID', value: "${CLOUD_FRONT_ID}"),
                                string(name: 'BUILD_COMMAND', value: "${BUILD_COMMAND}"),
                                string(name: 'CODE_FOLDER', value: "${CODE_FOLDER}"),
                                string(name: 'TESTS', value: "${TESTS}"),
                                string(name: 'BUILD_USER', value: "${BUILD_USER}"),
                                string(name: 'USER_EMAIL', value: "${USER_EMAIL}")
                                ]
                break;
            case "architecture":
                //Set Cluster Name
                def CLUSTER_NAME = ""
                //BUILD JOB
                build job: 'cd', propagate: false, wait: false, parameters: [
                                string(name: 'TESTS', value: "${TESTS}"),
                                string(name: 'BUILD_USER', value: "${BUILD_USER}"),
                                string(name: 'USER_EMAIL', value: "${USER_EMAIL}")
                                ]
                break;
            default:
                echo "Tipo de projeto não identificado"
                break;
        }
    }

} catch (err) {
    
	stage("Error") {
		currentBuild.result = 'FAILURE'
        echo "Error>>> " + err		
	}

} finally {
    
	stage("Limpeza do pipeline"){
		sh "sudo rm -rf *"	
        sh "sudo rm -rf .e*"
        sh "sudo rm -rf .g*"
        sh "sudo rm -rf .m*"
        sh "sudo rm -rf .s*"
        sh "sudo rm -rf .v*"
    }
  }
}
