"""secubox-hexo — FastAPI application for Hexo static blog management.

SecuBox module for managing Hexo static site generator.
Provides blog creation, theme/plugin management, post editing, and deployment.
"""
import asyncio
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-hexo", version="1.0.0", root_path="/api/v1/hexo")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("hexo")

# Configuration
CONFIG_FILE = Path("/etc/secubox/hexo.toml")
CONTAINER_NAME = "secbx-hexo"
BLOGS_PATH = Path("/srv/hexo/blogs")
DEFAULT_CONFIG = {
    "enabled": False,
    "image": "node:20-alpine",
    "blogs_path": "/srv/hexo/blogs",
    "preview_port": 4000,
    "default_theme": "landscape",
}


# ============================================================================
# Models
# ============================================================================

class HexoConfig(BaseModel):
    enabled: bool = False
    image: str = "node:20-alpine"
    blogs_path: str = "/srv/hexo/blogs"
    preview_port: int = 4000
    default_theme: str = "landscape"


class BlogCreate(BaseModel):
    name: str
    title: str = ""
    author: str = ""
    language: str = "en"


class BlogConfig(BaseModel):
    title: str = ""
    subtitle: str = ""
    author: str = ""
    language: str = "en"
    url: str = ""
    theme: str = "landscape"


class PostCreate(BaseModel):
    title: str
    slug: str = ""
    tags: List[str] = []
    categories: List[str] = []
    draft: bool = False


class PostUpdate(BaseModel):
    content: str


class ThemeInstall(BaseModel):
    name: str
    source: str  # git URL or npm package


class PluginInstall(BaseModel):
    name: str


class DeployConfig(BaseModel):
    type: str = "git"  # git, rsync, ftp, sftp
    repo: str = ""
    branch: str = "main"
    message: str = "Site updated"


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load hexo configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save hexo configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Hexo configuration"]
    for k, v in config.items():
        if isinstance(v, bool):
            lines.append(f"{k} = {str(v).lower()}")
        elif isinstance(v, int):
            lines.append(f"{k} = {v}")
        elif isinstance(v, list):
            lines.append(f'{k} = {v}')
        else:
            lines.append(f'{k} = "{v}"')
    CONFIG_FILE.write_text("\n".join(lines) + "\n")


def detect_runtime() -> Optional[str]:
    """Detect container runtime."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def get_container_status() -> dict:
    """Get Hexo container status."""
    rt = detect_runtime()
    if not rt:
        return {"status": "no_runtime", "uptime": ""}

    try:
        # Check if running
        result = subprocess.run(
            [rt, "ps", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return {"status": "running", "uptime": result.stdout.strip()}

        # Check if exists but stopped
        result = subprocess.run(
            [rt, "ps", "-a", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return {"status": "stopped", "uptime": ""}

        return {"status": "not_installed", "uptime": ""}
    except Exception:
        return {"status": "error", "uptime": ""}


def is_running() -> bool:
    """Check if Hexo container is running."""
    return get_container_status()["status"] == "running"


def get_blogs_path() -> Path:
    """Get blogs base path."""
    cfg = get_config()
    return Path(cfg.get("blogs_path", "/srv/hexo/blogs"))


def list_blogs() -> List[dict]:
    """List all blogs."""
    blogs_path = get_blogs_path()
    if not blogs_path.exists():
        return []

    blogs = []
    for d in blogs_path.iterdir():
        if d.is_dir() and (d / "_config.yml").exists():
            # Parse basic info from _config.yml
            config_file = d / "_config.yml"
            title = d.name
            theme = "landscape"
            try:
                content = config_file.read_text()
                for line in content.split('\n'):
                    if line.startswith('title:'):
                        title = line.split(':', 1)[1].strip().strip('"\'')
                    elif line.startswith('theme:'):
                        theme = line.split(':', 1)[1].strip().strip('"\'')
            except Exception:
                pass

            # Count posts
            posts_path = d / "source" / "_posts"
            post_count = len(list(posts_path.glob("*.md"))) if posts_path.exists() else 0

            blogs.append({
                "name": d.name,
                "title": title,
                "theme": theme,
                "posts": post_count,
                "path": str(d),
            })

    return blogs


def run_hexo_command(blog_name: str, command: List[str], timeout: int = 120) -> dict:
    """Run Hexo command in container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    blogs_path = get_blogs_path()
    blog_path = blogs_path / blog_name

    if not blog_path.exists():
        return {"success": False, "error": "Blog not found"}

    try:
        cfg = get_config()
        image = cfg.get("image", "node:20-alpine")

        cmd = [
            rt, "run", "--rm",
            "-v", f"{blog_path}:/app",
            "-w", "/app",
            image,
            "npx"
        ] + command

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else "",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "hexo"}


@router.get("/status")
async def status():
    """Get Hexo service status."""
    cfg = get_config()
    rt = detect_runtime()
    container = get_container_status()
    blogs = list_blogs()

    # Disk usage
    disk_usage = ""
    blogs_path = get_blogs_path()
    if blogs_path.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(blogs_path)],
                capture_output=True, text=True, timeout=10
            )
            disk_usage = result.stdout.split()[0] if result.stdout else ""
        except Exception:
            pass

    return {
        "enabled": cfg.get("enabled", False),
        "image": cfg.get("image", "node:20-alpine"),
        "blogs_path": cfg.get("blogs_path", "/srv/hexo/blogs"),
        "preview_port": cfg.get("preview_port", 4000),
        "default_theme": cfg.get("default_theme", "landscape"),
        "docker_available": rt is not None,
        "runtime": rt or "none",
        "container_status": container["status"],
        "container_uptime": container["uptime"],
        "disk_usage": disk_usage,
        "blog_count": len(blogs),
        "blogs": blogs,
    }


# ============================================================================
# Protected Endpoints
# ============================================================================

@router.get("/config")
async def get_hexo_config(user=Depends(require_jwt)):
    """Get Hexo configuration."""
    return get_config()


@router.post("/config")
async def set_hexo_config(config: HexoConfig, user=Depends(require_jwt)):
    """Update Hexo configuration."""
    cfg = get_config()
    cfg.update(config.dict())
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Blog Management
# ============================================================================

@router.get("/blogs")
async def get_blogs(user=Depends(require_jwt)):
    """List all blogs."""
    return {"blogs": list_blogs()}


@router.post("/blog/create")
async def create_blog(blog: BlogCreate, user=Depends(require_jwt)):
    """Create a new Hexo blog."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    blogs_path = get_blogs_path()
    blog_path = blogs_path / blog.name

    if blog_path.exists():
        return {"success": False, "error": "Blog already exists"}

    log.info(f"Creating blog {blog.name} by {user.get('sub', 'unknown')}")

    try:
        blogs_path.mkdir(parents=True, exist_ok=True)
        cfg = get_config()
        image = cfg.get("image", "node:20-alpine")

        # Initialize Hexo blog
        cmd = [
            rt, "run", "--rm",
            "-v", f"{blogs_path}:/blogs",
            "-w", "/blogs",
            image,
            "sh", "-c",
            f"npm install -g hexo-cli && hexo init {blog.name} && cd {blog.name} && npm install"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip(), "output": result.stdout}

        # Update config with user settings
        if blog.title or blog.author or blog.language != "en":
            config_file = blog_path / "_config.yml"
            if config_file.exists():
                content = config_file.read_text()
                if blog.title:
                    content = content.replace("title: Hexo", f"title: {blog.title}")
                if blog.author:
                    content = content.replace("author: John Doe", f"author: {blog.author}")
                if blog.language:
                    content = content.replace("language: en", f"language: {blog.language}")
                config_file.write_text(content)

        return {"success": True, "name": blog.name}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Creation timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.delete("/blog/{name}")
async def delete_blog(name: str, user=Depends(require_jwt)):
    """Delete a blog."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name

    if not blog_path.exists():
        return {"success": False, "error": "Blog not found"}

    log.info(f"Deleting blog {name} by {user.get('sub', 'unknown')}")

    try:
        shutil.rmtree(blog_path)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/blog/{name}/config")
async def get_blog_config(name: str, user=Depends(require_jwt)):
    """Get blog configuration."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name
    config_file = blog_path / "_config.yml"

    if not config_file.exists():
        raise HTTPException(404, "Blog not found")

    # Parse YAML manually (simple key: value extraction)
    config = {}
    try:
        content = config_file.read_text()
        for line in content.split('\n'):
            line = line.strip()
            if ':' in line and not line.startswith('#'):
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip().strip('"\'')
                if key in ['title', 'subtitle', 'author', 'language', 'url', 'theme']:
                    config[key] = value
    except Exception as e:
        return {"error": str(e)}

    return config


@router.post("/blog/{name}/config")
async def set_blog_config(name: str, config: BlogConfig, user=Depends(require_jwt)):
    """Update blog configuration."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name
    config_file = blog_path / "_config.yml"

    if not config_file.exists():
        raise HTTPException(404, "Blog not found")

    log.info(f"Updating blog {name} config by {user.get('sub', 'unknown')}")

    try:
        content = config_file.read_text()
        lines = content.split('\n')
        new_lines = []

        updates = {
            'title': config.title,
            'subtitle': config.subtitle,
            'author': config.author,
            'language': config.language,
            'url': config.url,
            'theme': config.theme,
        }

        for line in lines:
            stripped = line.strip()
            replaced = False
            for key, value in updates.items():
                if stripped.startswith(f'{key}:') and value:
                    indent = len(line) - len(line.lstrip())
                    new_lines.append(' ' * indent + f'{key}: {value}')
                    replaced = True
                    break
            if not replaced:
                new_lines.append(line)

        config_file.write_text('\n'.join(new_lines))
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Post Management
# ============================================================================

@router.get("/blog/{name}/posts")
async def get_posts(name: str, user=Depends(require_jwt)):
    """List all posts in a blog."""
    blogs_path = get_blogs_path()
    posts_path = blogs_path / name / "source" / "_posts"
    drafts_path = blogs_path / name / "source" / "_drafts"

    posts = []

    # Published posts
    if posts_path.exists():
        for f in posts_path.glob("*.md"):
            try:
                content = f.read_text()
                title = f.stem
                date = ""
                tags = []
                categories = []

                # Parse front matter
                if content.startswith('---'):
                    parts = content.split('---', 2)
                    if len(parts) >= 3:
                        front_matter = parts[1]
                        for line in front_matter.split('\n'):
                            line = line.strip()
                            if line.startswith('title:'):
                                title = line.split(':', 1)[1].strip().strip('"\'')
                            elif line.startswith('date:'):
                                date = line.split(':', 1)[1].strip()
                            elif line.startswith('tags:'):
                                tags_str = line.split(':', 1)[1].strip()
                                if tags_str.startswith('['):
                                    tags = [t.strip().strip('"\'') for t in tags_str.strip('[]').split(',')]
                            elif line.startswith('categories:'):
                                cats_str = line.split(':', 1)[1].strip()
                                if cats_str.startswith('['):
                                    categories = [c.strip().strip('"\'') for c in cats_str.strip('[]').split(',')]

                posts.append({
                    "filename": f.name,
                    "title": title,
                    "date": date,
                    "tags": tags,
                    "categories": categories,
                    "draft": False,
                })
            except Exception:
                continue

    # Drafts
    if drafts_path.exists():
        for f in drafts_path.glob("*.md"):
            try:
                content = f.read_text()
                title = f.stem

                if content.startswith('---'):
                    parts = content.split('---', 2)
                    if len(parts) >= 3:
                        for line in parts[1].split('\n'):
                            if line.strip().startswith('title:'):
                                title = line.split(':', 1)[1].strip().strip('"\'')
                                break

                posts.append({
                    "filename": f.name,
                    "title": title,
                    "date": "",
                    "tags": [],
                    "categories": [],
                    "draft": True,
                })
            except Exception:
                continue

    # Sort by date descending
    posts.sort(key=lambda x: x.get('date', ''), reverse=True)

    return {"posts": posts}


@router.post("/blog/{name}/post")
async def create_post(name: str, post: PostCreate, user=Depends(require_jwt)):
    """Create a new post."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name

    if not blog_path.exists():
        raise HTTPException(404, "Blog not found")

    log.info(f"Creating post '{post.title}' in {name} by {user.get('sub', 'unknown')}")

    # Generate slug from title if not provided
    slug = post.slug or post.title.lower().replace(' ', '-').replace('_', '-')
    slug = ''.join(c for c in slug if c.isalnum() or c == '-')

    # Determine path
    if post.draft:
        posts_path = blog_path / "source" / "_drafts"
    else:
        posts_path = blog_path / "source" / "_posts"

    posts_path.mkdir(parents=True, exist_ok=True)

    filename = f"{slug}.md"
    filepath = posts_path / filename

    if filepath.exists():
        return {"success": False, "error": "Post with this slug already exists"}

    # Create front matter
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tags_str = ', '.join(post.tags) if post.tags else ''
    cats_str = ', '.join(post.categories) if post.categories else ''

    content = f"""---
title: {post.title}
date: {date}
tags: [{tags_str}]
categories: [{cats_str}]
---

Write your post content here...
"""

    try:
        filepath.write_text(content)
        return {"success": True, "filename": filename}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/blog/{name}/post/{filename}")
async def get_post(name: str, filename: str, user=Depends(require_jwt)):
    """Get post content."""
    blogs_path = get_blogs_path()

    # Check in both _posts and _drafts
    for folder in ["_posts", "_drafts"]:
        filepath = blogs_path / name / "source" / folder / filename
        if filepath.exists():
            return {
                "filename": filename,
                "content": filepath.read_text(),
                "draft": folder == "_drafts",
            }

    raise HTTPException(404, "Post not found")


@router.put("/blog/{name}/post/{filename}")
async def update_post(name: str, filename: str, post: PostUpdate, user=Depends(require_jwt)):
    """Update post content."""
    blogs_path = get_blogs_path()

    log.info(f"Updating post {filename} in {name} by {user.get('sub', 'unknown')}")

    # Check in both _posts and _drafts
    for folder in ["_posts", "_drafts"]:
        filepath = blogs_path / name / "source" / folder / filename
        if filepath.exists():
            try:
                filepath.write_text(post.content)
                return {"success": True}
            except Exception as e:
                return {"success": False, "error": str(e)}

    raise HTTPException(404, "Post not found")


@router.delete("/blog/{name}/post/{filename}")
async def delete_post(name: str, filename: str, user=Depends(require_jwt)):
    """Delete a post."""
    blogs_path = get_blogs_path()

    log.info(f"Deleting post {filename} from {name} by {user.get('sub', 'unknown')}")

    for folder in ["_posts", "_drafts"]:
        filepath = blogs_path / name / "source" / folder / filename
        if filepath.exists():
            try:
                filepath.unlink()
                return {"success": True}
            except Exception as e:
                return {"success": False, "error": str(e)}

    raise HTTPException(404, "Post not found")


@router.post("/blog/{name}/post/{filename}/publish")
async def publish_draft(name: str, filename: str, user=Depends(require_jwt)):
    """Publish a draft post."""
    blogs_path = get_blogs_path()
    draft_path = blogs_path / name / "source" / "_drafts" / filename
    posts_path = blogs_path / name / "source" / "_posts"

    if not draft_path.exists():
        raise HTTPException(404, "Draft not found")

    log.info(f"Publishing draft {filename} in {name} by {user.get('sub', 'unknown')}")

    try:
        posts_path.mkdir(parents=True, exist_ok=True)
        shutil.move(draft_path, posts_path / filename)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Theme Management
# ============================================================================

@router.get("/themes")
async def get_themes(user=Depends(require_jwt)):
    """List popular Hexo themes."""
    # Static list of popular themes
    themes = [
        {"name": "landscape", "description": "Default Hexo theme", "repo": "hexojs/hexo-theme-landscape"},
        {"name": "next", "description": "Elegant and powerful theme", "repo": "next-theme/hexo-theme-next"},
        {"name": "butterfly", "description": "Beautiful and feature-rich", "repo": "jerryc127/hexo-theme-butterfly"},
        {"name": "fluid", "description": "Material Design theme", "repo": "fluid-dev/hexo-theme-fluid"},
        {"name": "icarus", "description": "Feature-rich blog theme", "repo": "ppoffice/hexo-theme-icarus"},
        {"name": "cactus", "description": "Clean and minimal", "repo": "probberechts/hexo-theme-cactus"},
        {"name": "melody", "description": "Fast and powerful", "repo": "Molunerfinn/hexo-theme-melody"},
        {"name": "matery", "description": "Material Design", "repo": "blinkfox/hexo-theme-matery"},
    ]
    return {"themes": themes}


@router.get("/blog/{name}/themes")
async def get_blog_themes(name: str, user=Depends(require_jwt)):
    """List installed themes for a blog."""
    blogs_path = get_blogs_path()
    themes_path = blogs_path / name / "themes"

    if not themes_path.exists():
        return {"themes": []}

    themes = []
    for d in themes_path.iterdir():
        if d.is_dir():
            themes.append({"name": d.name, "path": str(d)})

    return {"themes": themes}


@router.post("/blog/{name}/theme/install")
async def install_theme(name: str, theme: ThemeInstall, user=Depends(require_jwt)):
    """Install a theme."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name
    themes_path = blog_path / "themes"

    if not blog_path.exists():
        raise HTTPException(404, "Blog not found")

    log.info(f"Installing theme {theme.name} for {name} by {user.get('sub', 'unknown')}")

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    try:
        themes_path.mkdir(parents=True, exist_ok=True)
        cfg = get_config()
        image = cfg.get("image", "node:20-alpine")

        # Clone theme from git
        source = theme.source
        if not source.startswith('http'):
            source = f"https://github.com/{source}.git"

        cmd = [
            rt, "run", "--rm",
            "-v", f"{themes_path}:/themes",
            "-w", "/themes",
            "alpine/git",
            "clone", "--depth", "1", source, theme.name
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/blog/{name}/theme/switch")
async def switch_theme(name: str, theme_name: str, user=Depends(require_jwt)):
    """Switch blog theme."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name
    config_file = blog_path / "_config.yml"

    if not config_file.exists():
        raise HTTPException(404, "Blog not found")

    log.info(f"Switching theme to {theme_name} for {name} by {user.get('sub', 'unknown')}")

    try:
        content = config_file.read_text()
        lines = []
        for line in content.split('\n'):
            if line.strip().startswith('theme:'):
                lines.append(f'theme: {theme_name}')
            else:
                lines.append(line)
        config_file.write_text('\n'.join(lines))
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Plugin Management
# ============================================================================

@router.get("/plugins")
async def get_plugins(user=Depends(require_jwt)):
    """List popular Hexo plugins."""
    plugins = [
        {"name": "hexo-generator-sitemap", "description": "Generate sitemap.xml"},
        {"name": "hexo-generator-feed", "description": "Generate RSS feed"},
        {"name": "hexo-generator-search", "description": "Local search support"},
        {"name": "hexo-deployer-git", "description": "Git deployment"},
        {"name": "hexo-deployer-rsync", "description": "Rsync deployment"},
        {"name": "hexo-deployer-sftp", "description": "SFTP deployment"},
        {"name": "hexo-renderer-marked", "description": "Markdown renderer"},
        {"name": "hexo-renderer-pug", "description": "Pug template renderer"},
        {"name": "hexo-renderer-sass", "description": "Sass CSS renderer"},
        {"name": "hexo-wordcount", "description": "Word count and reading time"},
        {"name": "hexo-lazyload-image", "description": "Lazy load images"},
        {"name": "hexo-abbrlink", "description": "Generate unique post URLs"},
    ]
    return {"plugins": plugins}


@router.get("/blog/{name}/plugins")
async def get_blog_plugins(name: str, user=Depends(require_jwt)):
    """List installed plugins for a blog."""
    blogs_path = get_blogs_path()
    package_json = blogs_path / name / "package.json"

    if not package_json.exists():
        return {"plugins": []}

    try:
        data = json.loads(package_json.read_text())
        deps = data.get("dependencies", {})
        plugins = [{"name": k, "version": v} for k, v in deps.items() if k.startswith("hexo-")]
        return {"plugins": plugins}
    except Exception:
        return {"plugins": []}


@router.post("/blog/{name}/plugin/install")
async def install_plugin(name: str, plugin: PluginInstall, user=Depends(require_jwt)):
    """Install a plugin."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name

    if not blog_path.exists():
        raise HTTPException(404, "Blog not found")

    log.info(f"Installing plugin {plugin.name} for {name} by {user.get('sub', 'unknown')}")

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    try:
        cfg = get_config()
        image = cfg.get("image", "node:20-alpine")

        cmd = [
            rt, "run", "--rm",
            "-v", f"{blog_path}:/app",
            "-w", "/app",
            image,
            "npm", "install", "--save", plugin.name
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.delete("/blog/{name}/plugin/{plugin_name}")
async def remove_plugin(name: str, plugin_name: str, user=Depends(require_jwt)):
    """Remove a plugin."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name

    if not blog_path.exists():
        raise HTTPException(404, "Blog not found")

    log.info(f"Removing plugin {plugin_name} from {name} by {user.get('sub', 'unknown')}")

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    try:
        cfg = get_config()
        image = cfg.get("image", "node:20-alpine")

        cmd = [
            rt, "run", "--rm",
            "-v", f"{blog_path}:/app",
            "-w", "/app",
            image,
            "npm", "uninstall", "--save", plugin_name
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Generate & Deploy
# ============================================================================

@router.post("/blog/{name}/generate")
async def generate_blog(name: str, user=Depends(require_jwt)):
    """Generate static files."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name

    if not blog_path.exists():
        raise HTTPException(404, "Blog not found")

    log.info(f"Generating blog {name} by {user.get('sub', 'unknown')}")

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    try:
        cfg = get_config()
        image = cfg.get("image", "node:20-alpine")

        cmd = [
            rt, "run", "--rm",
            "-v", f"{blog_path}:/app",
            "-w", "/app",
            image,
            "npx", "hexo", "generate"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip(), "output": result.stdout}

        return {"success": True, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/blog/{name}/clean")
async def clean_blog(name: str, user=Depends(require_jwt)):
    """Clean generated files."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name

    if not blog_path.exists():
        raise HTTPException(404, "Blog not found")

    log.info(f"Cleaning blog {name} by {user.get('sub', 'unknown')}")

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    try:
        cfg = get_config()
        image = cfg.get("image", "node:20-alpine")

        cmd = [
            rt, "run", "--rm",
            "-v", f"{blog_path}:/app",
            "-w", "/app",
            image,
            "npx", "hexo", "clean"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        return {"success": result.returncode == 0, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/blog/{name}/deploy")
async def deploy_blog(name: str, config: DeployConfig = None, user=Depends(require_jwt)):
    """Deploy the blog."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name

    if not blog_path.exists():
        raise HTTPException(404, "Blog not found")

    log.info(f"Deploying blog {name} by {user.get('sub', 'unknown')}")

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    try:
        cfg = get_config()
        image = cfg.get("image", "node:20-alpine")

        cmd = [
            rt, "run", "--rm",
            "-v", f"{blog_path}:/app",
            "-w", "/app",
            image,
            "npx", "hexo", "deploy"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip(), "output": result.stdout}

        return {"success": True, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Preview Server
# ============================================================================

@router.post("/blog/{name}/preview/start")
async def start_preview(name: str, user=Depends(require_jwt)):
    """Start preview server."""
    blogs_path = get_blogs_path()
    blog_path = blogs_path / name

    if not blog_path.exists():
        raise HTTPException(404, "Blog not found")

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    preview_name = f"hexo-preview-{name}"

    # Stop existing preview if running
    subprocess.run([rt, "stop", preview_name], capture_output=True, timeout=10)
    subprocess.run([rt, "rm", "-f", preview_name], capture_output=True, timeout=10)

    log.info(f"Starting preview for {name} by {user.get('sub', 'unknown')}")

    try:
        cfg = get_config()
        image = cfg.get("image", "node:20-alpine")
        port = cfg.get("preview_port", 4000)

        cmd = [
            rt, "run", "-d",
            "--name", preview_name,
            "-v", f"{blog_path}:/app",
            "-w", "/app",
            "-p", f"127.0.0.1:{port}:4000",
            image,
            "npx", "hexo", "server"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        await asyncio.sleep(2)

        # Check if running
        check = subprocess.run(
            [rt, "ps", "--filter", f"name={preview_name}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )

        if check.stdout.strip():
            return {"success": True, "port": port, "url": f"http://localhost:{port}"}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start preview"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/blog/{name}/preview/stop")
async def stop_preview(name: str, user=Depends(require_jwt)):
    """Stop preview server."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    preview_name = f"hexo-preview-{name}"

    log.info(f"Stopping preview for {name} by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", preview_name], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", preview_name], capture_output=True, timeout=10)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/blog/{name}/preview/status")
async def get_preview_status(name: str, user=Depends(require_jwt)):
    """Get preview server status."""
    rt = detect_runtime()
    if not rt:
        return {"running": False}

    preview_name = f"hexo-preview-{name}"

    try:
        result = subprocess.run(
            [rt, "ps", "--filter", f"name={preview_name}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )

        cfg = get_config()
        port = cfg.get("preview_port", 4000)

        return {
            "running": bool(result.stdout.strip()),
            "status": result.stdout.strip() or "stopped",
            "port": port,
        }
    except Exception:
        return {"running": False}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get container status."""
    return get_container_status()


@router.post("/container/install")
async def install_container(user=Depends(require_jwt)):
    """Pull Node.js image for Hexo."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    image = cfg.get("image", "node:20-alpine")

    log.info(f"Installing Hexo image ({image}) by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=300
        )

        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        # Also pull git image for theme installs
        subprocess.run([rt, "pull", "alpine/git"], capture_output=True, timeout=120)

        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/logs")
async def get_logs(lines: int = 50, user=Depends(require_jwt)):
    """Get container logs."""
    rt = detect_runtime()
    if not rt:
        return {"logs": "No container runtime"}

    try:
        result = subprocess.run(
            [rt, "logs", "--tail", str(lines), CONTAINER_NAME],
            capture_output=True, text=True, timeout=10
        )
        logs = result.stdout + result.stderr
        return {"logs": logs if logs.strip() else "No logs available"}
    except Exception:
        return {"logs": "No logs available"}


app.include_router(router)
