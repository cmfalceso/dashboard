@echo off
start "Data Generator" python generate_data.py
start "Dashboard" python -m streamlit run app.py