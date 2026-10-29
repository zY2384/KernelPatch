#! /bin/bash
git add .
git commit -m "sync hook"

#git push git@github.com:zY2384/KernelPatch.git

# 强制覆盖提交 多人合作不推荐
git push -f git@github.com:zY2384/KernelPatch.git

