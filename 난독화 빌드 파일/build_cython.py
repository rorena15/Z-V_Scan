# build_cython.py
import os
import sys
from setuptools import setup
from setuptools.extension import Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

# 1. 컴파일할 대상 패키지
target_dirs = [
    "scanner_engine/core",
    "scanner_engine/utils",
    "scanner_engine/output"
]

extensions = []

def find_py_files(dirs):
    for dir_path in dirs:
        # 경로가 존재하는지 확인
        if not os.path.exists(dir_path):
            print(f"[Skip] Directory not found: {dir_path}")
            continue
            
        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".py") and file != "__init__.py":
                    full_path = os.path.join(root, file)
                    
                    # [Fix] 확장자(.py) 제거
                    base_name = os.path.splitext(full_path)[0]
                    
                    # [Fix] Windows(\)와 Linux(/) 슬래시 모두 점(.)으로 강제 치환
                    # 이렇게 해야 'scanner_engine/core\advanced_scanner' 같은 혼종 경로가
                    # 'scanner_engine.core.advanced_scanner'로 깔끔하게 바뀝니다.
                    module_name = base_name.replace("\\", ".").replace("/", ".")
                    
                    print(f"[Target] {module_name}")
                    
                    extensions.append(
                        Extension(
                            module_name,
                            [full_path],
                            extra_compile_args=["/O2", "/W3"] if os.name == 'nt' else ["-O3", "-Wall"]
                        )
                    )

find_py_files(target_dirs)

if not extensions:
    print("❌ 컴파일할 대상 파일을 찾지 못했습니다. 경로를 확인해주세요.")
    sys.exit(1)

print(f"🚀 Starting Cython Compilation for {len(extensions)} files...")

try:
    setup(
        name="Z-VulnScan_Engine",
        ext_modules=cythonize(
            extensions,
            compiler_directives={'language_level': "3", 'always_allow_keywords': True},
            annotate=False
        ),
        cmdclass={'build_ext': build_ext}
    )
except Exception as e:
    print(f"\n❌ Compilation Failed: {e}")
    sys.exit(1)