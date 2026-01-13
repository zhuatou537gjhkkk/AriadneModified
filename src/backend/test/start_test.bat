@echo off
echo ====================================================================
echo FusionTrace ETL Pipeline - 实时监听测试
echo ====================================================================
echo.
echo 使用方法:
echo   1. 先运行此脚本启动 Pipeline (监听新增日志)
echo   2. 再打开新终端运行: python src/backend/simulate_logs.py
echo.
echo 按 Ctrl+C 停止
echo ====================================================================
echo.

cd src\backend
python -m app.etl.pipeline

pause
