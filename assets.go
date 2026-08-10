package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"time"
)

//go:embed web/assets/app.css
var appCSS []byte

//go:embed web/assets/app.js
var appJS []byte

type staticAsset struct {
	name, contentType string
	data              []byte
	digest            string
}

var embeddedAssets = func() map[string]staticAsset {
	assets := []staticAsset{
		{name: "app.css", contentType: "text/css; charset=utf-8", data: appCSS},
		{name: "app.js", contentType: "application/javascript; charset=utf-8", data: appJS},
	}
	result := make(map[string]staticAsset, len(assets))
	for _, asset := range assets {
		asset.digest = fmt.Sprintf("%x", sha256.Sum256(asset.data))
		result[asset.name] = asset
	}
	return result
}()

var assetModTime = time.Unix(0, 0).UTC()

func assetURL(name string) string {
	asset, ok := embeddedAssets[name]
	if !ok {
		return ""
	}
	base, extension, ok := strings.Cut(asset.name, ".")
	if !ok {
		return ""
	}
	return "/_assets/" + base + "." + asset.digest[:16] + "." + extension
}

func (s *server) serveAsset(w http.ResponseWriter, r *http.Request, name string) {
	for assetName, asset := range embeddedAssets {
		if assetURL(assetName) != "/_assets/"+name {
			continue
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("ETag", `"`+asset.digest+`"`)
		w.Header().Set("Content-Type", asset.contentType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, assetName, assetModTime, bytes.NewReader(asset.data))
		return
	}
	http.NotFound(w, r)
}
