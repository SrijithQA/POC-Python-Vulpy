pipeline {
    agent any

    environment {
        CLIENT_ID = '23e4567-e89b-12d3-a456-426614174001'
        CLIENT_SECRET = '67d4763ccd71b0d5c3acdd97e8ae7a1b'
        APPLICATION_ID = '69824a3929d55d0f43c04e8d'
        SCA_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sca-scans'
        SAST_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sast-scans'
    }

    stages {
        stage('Clean Up Old Files') {
            steps {
                script {
                    sh 'rm -rf venv'
                    sh 'rm -rf project.zip'
                    sh 'rm -rf *.json'
                    sh 'rm -rf *.csv'
                    sh 'rm -rf *.sh'
                }
            }
        }

        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Create ZIP Files') {
            steps {
                script {
                    sh 'rm -rf project_folder'
                    sh 'mkdir project_folder'
                    sh 'find . -maxdepth 1 -not -name "." -not -name ".." -not -name ".git" -not -name "venv" -not -name "project_folder" -exec mv {} project_folder/ \\;'
                    sh 'zip -r project.zip project_folder'
                }
            }
        }

        stage('Perform SCA Scan') {
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl -v -X POST                         -H "Client-ID: ${CLIENT_ID}"                         -H "Client-Secret: ${CLIENT_SECRET}"                         -F "projectZipFile=@project.zip"                         -F "applicationId=${APPLICATION_ID}"                         -F "scanName=Jenkins-python-vulpy-SCA Scan"                         -F "language=python"                         "${SCA_API_URL}"
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSCA = jsonResponse.canProceed
                    def vulnsTable = jsonResponse.vulnsTable

                    def cleanVulnsTable = vulnsTable.replaceAll("\\u001B\\[[;\\d]*m", "")

                    echo "Vulnerabilities found during SCA:"
                    echo "${cleanVulnsTable}"

                    env.CAN_PROCEED_SCA = canProceedSCA.toString()
                }
            }
        }

        stage('Perform SAST Scan') {
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl -v -X POST                         -H "Client-ID: ${CLIENT_ID}"                         -H "Client-Secret: ${CLIENT_SECRET}"                         -F "projectZipFile=@project.zip"                         -F "applicationId=${APPLICATION_ID}"                         -F "scanName=Jenkins-python-vulpy-SAST Scan"                         -F "language=python"                         "${SAST_API_URL}"
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSAST = jsonResponse.canProceed
                    def vulnsTable = jsonResponse.vulnsTable

                    def cleanVulnsTable = vulnsTable.replaceAll("\\u001B\\[[;\\d]*m", "")

                    echo "Vulnerabilities found during SAST:"
                    echo "${cleanVulnsTable}"

                    env.CAN_PROCEED_SAST = canProceedSAST.toString()
                }
            }
        }

        // Additional stages (e.g., deploy) can be added here
    }
}





