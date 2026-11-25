#!/bin/bash
# Build the two bundles Terraform uploads. The student bundle contains NO instructor docs or scripts.
set -e; cd "$(dirname "$0")/.."; mkdir -p dist
tar czf dist/student.tar.gz range scripts/gen_compose.py scripts/labctl.sh docs/STUDENT_HANDOUT.md
tar czf dist/instructor.tar.gz range scripts docs
echo "built dist/student.tar.gz dist/instructor.tar.gz"
