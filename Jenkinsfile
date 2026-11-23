// Jenkinsfile - Pipeline de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
//
// Esta es la versión BASE: construye, prueba y despliega en producción.
// Los marcadores  >>> [ETIQUETA]  indican dónde agregar las etapas de seguridad.

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
        SAST_OK = 'false'
        DEP_OK = 'false'
        ZAP_OK = 'false'
        ZAP_MINUTOS_ACTIVO = '3'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    def sha = sh(
                        returnStdout: true,
                        script: 'git rev-parse --short HEAD'
                    ).trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }

                echo "Version: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true,
                        testResults: 'reports/junit.xml'
                }
            }
        }

        stage('Security Review (SAST)') {
            steps {
                script {
                    int resultado = sh(
                        returnStatus: true,
                        script: 'bandit -q -ll app.py > reports/bandit.txt 2>&1'
                    )

                    sh 'cat reports/bandit.txt'

                    env.SAST_OK = resultado == 0 ? 'true' : 'false'

                    if (resultado != 0) {
                        unstable('Bandit detecto hallazgos o fallo el analisis')
                    }
                }
            }
        }

        stage('Dependency Management') {
            steps {
                script {
                    int resultado = sh(
                        returnStatus: true,
                        script: 'pip-audit -r requirements.txt > reports/pip-audit.txt 2>&1'
                    )

                    sh 'cat reports/pip-audit.txt'

                    env.DEP_OK = resultado == 0 ? 'true' : 'false'

                    if (resultado != 0) {
                        unstable('Dependencias vulnerables o fallo la auditoria')
                    }
                }
            }
        }

        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    int resultado = sh(
                        returnStatus: true,
                        script: 'python3 scripts/zap_scan.py http://jenkins:5001'
                    )

                    env.ZAP_OK = resultado == 0 ? 'true' : 'false'

                    if (resultado != 0) {
                        unstable('ZAP detecto alertas o no completo el analisis')
                    }
                }
            }
        }

        stage('Deploy Producción') {
            when {
                expression {
                    return env.SAST_OK == 'true' &&
                        env.DEP_OK == 'true' &&
                        env.ZAP_OK == 'true'
                }
            }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script {
                    env.PRODUCCION = env.APP_VERSION
                }
            }
        }
    }

    post {
        always {
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }

            archiveArtifacts(
                artifacts: 'reports/**',
                allowEmptyArchive: true
            )
        }
    }
}
