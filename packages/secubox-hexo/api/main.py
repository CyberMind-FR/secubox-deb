#!/usr/bin/env python3
"""SecuBox Hexo API - Static Blog Generator Management"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import subprocess
import os
import json
import shutil
from pathlib import Path
from datetime import datetime

app = FastAPI(title="SecuBox Hexo API", version="1.0.0")

HEXO_BASE = Path("/var/lib/secubox/hexo")
HEXO_SITES = HEXO_BASE / "sites"
HEXO_OUTPUT = Path("/var/www/hexo")


class SiteCreate(BaseModel):
    name: str
    title: str
    author: Optional[str] = "SecuBox"
    theme: Optional[str] = "landscape"


class PostCreate(BaseModel):
    site: str
    title: str
    content: str
    tags: Optional[List[str]] = []
    categories: Optional[List[str]] = []


class PostUpdate(BaseModel):
    content: str


def run_cmd(cmd: list, cwd: str = None, timeout: int = 120) -> dict:
    """Run command and return result"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "hexo"}


@app.get("/status")
async def status():
    """Get Hexo installation status"""
    # Check if hexo-cli is installed
    hexo_check = run_cmd(["which", "hexo"])
    npm_check = run_cmd(["which", "npm"])
    node_check = run_cmd(["node", "--version"])

    sites = []
    if HEXO_SITES.exists():
        for site_dir in HEXO_SITES.iterdir():
            if site_dir.is_dir() and (site_dir / "_config.yml").exists():
                sites.append(site_dir.name)

    return {
        "installed": hexo_check["success"],
        "hexo_path": hexo_check.get("stdout", "").strip() if hexo_check["success"] else None,
        "node_version": node_check.get("stdout", "").strip() if node_check["success"] else None,
        "npm_available": npm_check["success"],
        "sites_count": len(sites),
        "sites": sites,
        "base_path": str(HEXO_BASE),
        "output_path": str(HEXO_OUTPUT)
    }


@app.post("/install")
async def install():
    """Install Hexo CLI globally"""
    # Ensure npm is available
    npm_check = run_cmd(["which", "npm"])
    if not npm_check["success"]:
        raise HTTPException(status_code=400, detail="npm is not installed. Please install nodejs first.")

    # Install hexo-cli globally
    result = run_cmd(["npm", "install", "-g", "hexo-cli"], timeout=300)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Failed to install hexo-cli: {result.get('stderr', result.get('error'))}")

    # Create base directories
    HEXO_SITES.mkdir(parents=True, exist_ok=True)
    HEXO_OUTPUT.mkdir(parents=True, exist_ok=True)

    return {"success": True, "message": "Hexo CLI installed successfully"}


@app.get("/sites")
async def list_sites():
    """List all Hexo sites"""
    sites = []
    if HEXO_SITES.exists():
        for site_dir in HEXO_SITES.iterdir():
            if site_dir.is_dir():
                config_file = site_dir / "_config.yml"
                if config_file.exists():
                    # Parse basic config
                    config = {}
                    with open(config_file) as f:
                        for line in f:
                            if ":" in line and not line.strip().startswith("#"):
                                key, _, val = line.partition(":")
                                config[key.strip()] = val.strip()

                    # Count posts
                    posts_dir = site_dir / "source" / "_posts"
                    post_count = len(list(posts_dir.glob("*.md"))) if posts_dir.exists() else 0

                    # Check if deployed
                    deployed = (HEXO_OUTPUT / site_dir.name / "index.html").exists()

                    sites.append({
                        "name": site_dir.name,
                        "title": config.get("title", site_dir.name),
                        "author": config.get("author", ""),
                        "theme": config.get("theme", "landscape"),
                        "post_count": post_count,
                        "deployed": deployed,
                        "path": str(site_dir)
                    })

    return {"sites": sites}


@app.post("/sites")
async def create_site(site: SiteCreate):
    """Create a new Hexo site"""
    site_path = HEXO_SITES / site.name

    if site_path.exists():
        raise HTTPException(status_code=400, detail=f"Site '{site.name}' already exists")

    # Create site directory
    HEXO_SITES.mkdir(parents=True, exist_ok=True)

    # Initialize hexo site
    result = run_cmd(["hexo", "init", site.name], cwd=str(HEXO_SITES), timeout=300)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Failed to initialize site: {result.get('stderr', result.get('error'))}")

    # Install dependencies
    result = run_cmd(["npm", "install"], cwd=str(site_path), timeout=300)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Failed to install dependencies: {result.get('stderr')}")

    # Update config
    config_file = site_path / "_config.yml"
    if config_file.exists():
        with open(config_file) as f:
            config = f.read()

        config = config.replace("title: Hexo", f"title: {site.title}")
        config = config.replace("author: John Doe", f"author: {site.author}")

        with open(config_file, "w") as f:
            f.write(config)

    # Install theme if not default
    if site.theme and site.theme != "landscape":
        theme_result = run_cmd(
            ["npm", "install", f"hexo-theme-{site.theme}"],
            cwd=str(site_path), timeout=300
        )
        if theme_result["success"]:
            # Update theme in config
            with open(config_file) as f:
                config = f.read()
            config = config.replace("theme: landscape", f"theme: {site.theme}")
            with open(config_file, "w") as f:
                f.write(config)

    return {"success": True, "name": site.name, "path": str(site_path)}


@app.delete("/sites/{name}")
async def delete_site(name: str):
    """Delete a Hexo site"""
    site_path = HEXO_SITES / name
    output_path = HEXO_OUTPUT / name

    if not site_path.exists():
        raise HTTPException(status_code=404, detail=f"Site '{name}' not found")

    # Remove site directory
    shutil.rmtree(site_path)

    # Remove output if exists
    if output_path.exists():
        shutil.rmtree(output_path)

    return {"success": True, "message": f"Site '{name}' deleted"}


@app.get("/sites/{name}/posts")
async def list_posts(name: str):
    """List posts in a site"""
    site_path = HEXO_SITES / name
    posts_dir = site_path / "source" / "_posts"

    if not site_path.exists():
        raise HTTPException(status_code=404, detail=f"Site '{name}' not found")

    posts = []
    if posts_dir.exists():
        for post_file in posts_dir.glob("*.md"):
            with open(post_file) as f:
                content = f.read()

            # Parse front matter
            title = post_file.stem
            date = datetime.fromtimestamp(post_file.stat().st_mtime).isoformat()
            tags = []
            categories = []

            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    front_matter = parts[1]
                    for line in front_matter.split("\n"):
                        if line.startswith("title:"):
                            title = line.split(":", 1)[1].strip().strip("'\"")
                        elif line.startswith("date:"):
                            date = line.split(":", 1)[1].strip()

            posts.append({
                "filename": post_file.name,
                "title": title,
                "date": date,
                "size": post_file.stat().st_size
            })

    return {"site": name, "posts": sorted(posts, key=lambda x: x["date"], reverse=True)}


@app.post("/sites/{name}/posts")
async def create_post(name: str, post: PostCreate):
    """Create a new post"""
    site_path = HEXO_SITES / name
    posts_dir = site_path / "source" / "_posts"

    if not site_path.exists():
        raise HTTPException(status_code=404, detail=f"Site '{name}' not found")

    posts_dir.mkdir(parents=True, exist_ok=True)

    # Generate filename from title
    slug = post.title.lower().replace(" ", "-").replace("'", "")
    filename = f"{slug}.md"
    post_path = posts_dir / filename

    if post_path.exists():
        raise HTTPException(status_code=400, detail=f"Post '{filename}' already exists")

    # Create post with front matter
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    front_matter = f"""---
title: {post.title}
date: {now}
tags: [{', '.join(post.tags)}]
categories: [{', '.join(post.categories)}]
---

{post.content}
"""

    with open(post_path, "w") as f:
        f.write(front_matter)

    return {"success": True, "filename": filename, "path": str(post_path)}


@app.get("/sites/{name}/posts/{filename}")
async def get_post(name: str, filename: str):
    """Get post content"""
    site_path = HEXO_SITES / name
    post_path = site_path / "source" / "_posts" / filename

    if not post_path.exists():
        raise HTTPException(status_code=404, detail=f"Post '{filename}' not found")

    with open(post_path) as f:
        content = f.read()

    return {"filename": filename, "content": content}


@app.put("/sites/{name}/posts/{filename}")
async def update_post(name: str, filename: str, post: PostUpdate):
    """Update post content"""
    site_path = HEXO_SITES / name
    post_path = site_path / "source" / "_posts" / filename

    if not post_path.exists():
        raise HTTPException(status_code=404, detail=f"Post '{filename}' not found")

    with open(post_path, "w") as f:
        f.write(post.content)

    return {"success": True, "filename": filename}


@app.delete("/sites/{name}/posts/{filename}")
async def delete_post(name: str, filename: str):
    """Delete a post"""
    site_path = HEXO_SITES / name
    post_path = site_path / "source" / "_posts" / filename

    if not post_path.exists():
        raise HTTPException(status_code=404, detail=f"Post '{filename}' not found")

    post_path.unlink()
    return {"success": True, "message": f"Post '{filename}' deleted"}


@app.post("/sites/{name}/generate")
async def generate_site(name: str):
    """Generate static files for a site"""
    site_path = HEXO_SITES / name

    if not site_path.exists():
        raise HTTPException(status_code=404, detail=f"Site '{name}' not found")

    # Clean and generate
    result = run_cmd(["hexo", "clean"], cwd=str(site_path))
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Failed to clean: {result.get('stderr')}")

    result = run_cmd(["hexo", "generate"], cwd=str(site_path), timeout=300)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Failed to generate: {result.get('stderr')}")

    return {"success": True, "message": "Site generated successfully"}


@app.post("/sites/{name}/deploy")
async def deploy_site(name: str):
    """Deploy generated site to web root"""
    site_path = HEXO_SITES / name
    public_dir = site_path / "public"
    output_dir = HEXO_OUTPUT / name

    if not site_path.exists():
        raise HTTPException(status_code=404, detail=f"Site '{name}' not found")

    if not public_dir.exists():
        raise HTTPException(status_code=400, detail="Site not generated. Run generate first.")

    # Remove old deployment
    if output_dir.exists():
        shutil.rmtree(output_dir)

    # Copy public to output
    shutil.copytree(public_dir, output_dir)

    return {
        "success": True,
        "message": f"Site deployed to {output_dir}",
        "url": f"/hexo-sites/{name}/"
    }


@app.get("/themes")
async def list_themes():
    """List popular Hexo themes"""
    return {
        "themes": [
            {"name": "landscape", "description": "Default Hexo theme", "builtin": True},
            {"name": "next", "description": "Elegant theme for Hexo", "npm": "hexo-theme-next"},
            {"name": "butterfly", "description": "Beautiful theme with animations", "npm": "hexo-theme-butterfly"},
            {"name": "fluid", "description": "Material Design theme", "npm": "hexo-theme-fluid"},
            {"name": "icarus", "description": "Feature-rich theme", "npm": "hexo-theme-icarus"},
            {"name": "matery", "description": "Material Design blog theme", "npm": "hexo-theme-matery"}
        ]
    }


@app.post("/sites/{name}/themes/{theme}")
async def install_theme(name: str, theme: str):
    """Install a theme for a site"""
    site_path = HEXO_SITES / name

    if not site_path.exists():
        raise HTTPException(status_code=404, detail=f"Site '{name}' not found")

    # Install theme
    result = run_cmd(
        ["npm", "install", f"hexo-theme-{theme}"],
        cwd=str(site_path), timeout=300
    )

    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Failed to install theme: {result.get('stderr')}")

    # Update config
    config_file = site_path / "_config.yml"
    if config_file.exists():
        with open(config_file) as f:
            config = f.read()

        # Replace theme line
        import re
        config = re.sub(r'^theme:.*$', f'theme: {theme}', config, flags=re.MULTILINE)

        with open(config_file, "w") as f:
            f.write(config)

    return {"success": True, "message": f"Theme '{theme}' installed and activated"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
