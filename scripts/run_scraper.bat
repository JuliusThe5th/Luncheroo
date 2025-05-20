@echo off
cd /d %~dp0\..
call .venv\Scripts\activate
python scripts/czech_lunch_scraper.py 