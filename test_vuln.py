import os
def execute_user_query(query):
    # This is highly insecure
    os.system(f"echo {query}")
