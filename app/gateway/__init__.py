"""The tool gateway: the one way from the agent to a tool.

    manifest.py  what the reviewed capability manifests say about each tool
    auth.py      who is calling (Kubernetes: a TokenReview), and which pod
    proxy.py     the checks every call passes, the risk engine client, the tool client
    server.py    the MCP server the agent talks to (port 8080)
    main.py      the process: ops port 9000, heartbeat, uvicorn
"""
