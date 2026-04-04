# secubox-hexo

SecuBox module for managing Hexo static site generator via Docker/Podman.

## Features

- **Blog Management**: Create, configure, and delete multiple Hexo blogs
- **Post Editor**: Create and edit posts with markdown preview
- **Draft Workflow**: Save posts as drafts and publish when ready
- **Theme Gallery**: Browse and install popular Hexo themes
- **Plugin Management**: Install plugins for sitemap, RSS, search, etc.
- **Preview Server**: Live preview with hot reload
- **Static Generation**: Generate optimized static files
- **Deployment**: Deploy to Git, rsync, SFTP targets
- **Container-based**: Runs in Docker/Podman for isolation

## API Endpoints

All endpoints require JWT authentication except `/health` and `/status`.

### Status
- `GET /health` - Health check
- `GET /status` - Service status with blog list

### Configuration
- `GET /config` - Get Hexo configuration
- `POST /config` - Update configuration

### Blog Management
- `GET /blogs` - List all blogs
- `POST /blog/create` - Create new blog
- `DELETE /blog/{name}` - Delete blog
- `GET /blog/{name}/config` - Get blog config
- `POST /blog/{name}/config` - Update blog config

### Post Management
- `GET /blog/{name}/posts` - List posts
- `POST /blog/{name}/post` - Create post
- `GET /blog/{name}/post/{filename}` - Get post content
- `PUT /blog/{name}/post/{filename}` - Update post
- `DELETE /blog/{name}/post/{filename}` - Delete post
- `POST /blog/{name}/post/{filename}/publish` - Publish draft

### Themes
- `GET /themes` - List available themes
- `GET /blog/{name}/themes` - List installed themes
- `POST /blog/{name}/theme/install` - Install theme
- `POST /blog/{name}/theme/switch` - Switch theme

### Plugins
- `GET /plugins` - List available plugins
- `GET /blog/{name}/plugins` - List installed plugins
- `POST /blog/{name}/plugin/install` - Install plugin
- `DELETE /blog/{name}/plugin/{name}` - Remove plugin

### Build & Deploy
- `POST /blog/{name}/generate` - Generate static files
- `POST /blog/{name}/clean` - Clean generated files
- `POST /blog/{name}/deploy` - Deploy blog

### Preview
- `POST /blog/{name}/preview/start` - Start preview server
- `POST /blog/{name}/preview/stop` - Stop preview server
- `GET /blog/{name}/preview/status` - Get preview status

### Container
- `GET /container/status` - Container status
- `POST /container/install` - Pull Node.js image
- `GET /logs` - Container logs

## Configuration

Configuration file: `/etc/secubox/hexo.toml`

```toml
enabled = true
image = "node:20-alpine"
blogs_path = "/srv/hexo/blogs"
preview_port = 4000
default_theme = "landscape"
```

## Data Paths

- Blogs: `/srv/hexo/blogs/{blog-name}/`
- Configuration: `/etc/secubox/hexo.toml`

## Frontend

Web interface available at `/hexo/` featuring:
- P31 Phosphor light theme with orange (#fb923c) accent
- Blog cards with quick actions
- Tabbed interface: Blogs, Posts, Themes, Plugins, Logs, Settings
- Post editor with live markdown preview
- Theme gallery with install buttons
- Toast notifications

## Popular Themes

- landscape (default)
- next - Elegant and powerful
- butterfly - Beautiful and feature-rich
- fluid - Material Design
- icarus - Feature-rich
- cactus - Clean and minimal

## Popular Plugins

- hexo-generator-sitemap
- hexo-generator-feed
- hexo-generator-search
- hexo-deployer-git
- hexo-wordcount

## Service Management

```bash
# Status
systemctl status secubox-hexo

# Restart
systemctl restart secubox-hexo

# Logs
journalctl -u secubox-hexo -f
```

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
