# CI/CD Integration

## GitHub Actions

```yaml
name: aisentry Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install aisentry
      - run: aisentry scan . -o sarif -f results.sarif
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### With HTML Report Artifact

```yaml
name: aisentry Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install aisentry
      - run: aisentry scan . -o html -f security-report.html
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.html
```

### Fail on High Severity

```yaml
name: aisentry Security Gate
on: [pull_request]
jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install aisentry
      - run: aisentry scan . -s high -o json -f results.json
      - name: Check for high severity issues
        run: |
          count=$(jq '.findings | length' results.json)
          if [ "$count" -gt 0 ]; then
            echo "Found $count high+ severity issues"
            exit 1
          fi
```

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: aisentry-scan
        name: aisentry Security Scan
        entry: aisentry scan
        language: system
        types: [python]
        args: ['-s', 'high', '-q']
```

## GitLab CI

```yaml
security-scan:
  image: python:3.11
  script:
    - pip install aisentry
    - aisentry scan . -o json -f gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
  - script: pip install aisentry
  - script: aisentry scan . -o sarif -f results.sarif
  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: results.sarif
      artifactName: security-results
```

## Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install aisentry'
                sh 'aisentry scan . -o html -f security-report.html'
                publishHTML([
                    reportName: 'Security Report',
                    reportDir: '.',
                    reportFiles: 'security-report.html'
                ])
            }
        }
    }
}
```
