// Copyright (c) seasonjs. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/schollz/progressbar/v3"
)

type RepoType int

const (
	Model RepoType = iota
	Dataset
	Space
)

type Cache struct {
	path   string
	resume bool
}

func NewCache(path string, resume bool) *Cache {
	return &Cache{path: path, resume: resume}
}

func DefaultCache() (*Cache, error) {
	homePath := os.Getenv("HF_HOME")
	if len(homePath) == 0 {
		var err error
		homePath, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		homePath = filepath.Join(homePath, ".cache", "huggingface")
	}
	cachePath := filepath.Join(homePath, "hub")
	return NewCache(cachePath, true), nil
}

func (c *Cache) Path() string {
	return c.path
}

func (c *Cache) TokenPath() string {
	return filepath.Join(filepath.Dir(c.path), "token")
}

func (c *Cache) Token() (string, error) {
	tokenPath := c.TokenPath()
	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		log.Println("auth token file not found")
		return "", nil
	}

	file, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(file))
	if len(token) == 0 {
		return "", errors.New("token file empty")
	}
	return token, nil
}

func (c *Cache) Repo(rep *Repo) *CacheRepo {
	return NewCacheRepo(c.Clone(), rep)
}

func (c *Cache) Model(modelId string) *CacheRepo {
	return c.Repo(NewRepo(modelId, Model))
}

func (c *Cache) Dataset(modelId string) *CacheRepo {
	return c.Repo(NewRepo(modelId, Dataset))
}

func (c *Cache) Space(modelId string) *CacheRepo {
	return c.Repo(NewRepo(modelId, Space))
}

func (c *Cache) TempPath(filename string) (string, error) {
	path := filepath.Join(c.path, "tmp")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return "", err
	}

	if len(filename) > 0 {
		if c.resume {
			path = filepath.Join(path, filename+".income")
		} else {
			path = filepath.Join(path, filename+randStr(7))
		}
	} else {
		path = filepath.Join(path, randStr(7))
	}

	return path, nil
}

func (c *Cache) Clone() *Cache {
	newCache := NewCache(c.path, c.resume)
	return newCache
}

type CacheRepo struct {
	cache *Cache
	repo  *Repo
}

func NewCacheRepo(cache *Cache, repo *Repo) *CacheRepo {
	return &CacheRepo{repo: repo, cache: cache}
}

func (r *CacheRepo) Get(filename string) (string, error) {
	commitPath := r.refPath()
	if _, err := os.Stat(commitPath); err != nil {
		return "", err
	}

	commitHash, err := os.ReadFile(commitPath)
	if err != nil {
		return "", err
	}

	path := r.PointerPath(string(commitHash))
	path = filepath.Join(path, filename)
	if _, err = os.Stat(path); err != nil {
		return "", err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	return absPath, nil
}

func (r *CacheRepo) path() string {
	return filepath.Join(r.cache.path, r.repo.FolderName())
}

func (r *CacheRepo) refPath() string {
	path := r.path()
	return filepath.Join(path, "refs", r.repo.Revision())
}

func (r *CacheRepo) CreateRef(commitHash string) error {
	refPath := r.refPath()
	err := os.MkdirAll(filepath.Dir(refPath), os.ModePerm)
	if err != nil {
		return err
	}
	err = os.WriteFile(refPath, []byte(commitHash), os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func (r *CacheRepo) BlobPath(etag string) string {
	return filepath.Join(r.path(), "blobs", etag)
}

func (r *CacheRepo) PointerPath(commitHash string) string {
	return filepath.Join(r.path(), "snapshots", commitHash)
}

type Repo struct {
	repoId   string
	repoType RepoType
	revision string
}

func NewRepo(repoId string, repoType RepoType) *Repo {
	return NewRepoWithRevision(repoId, repoType, "main")
}

func NewRepoWithRevision(repoId string, repoType RepoType, revision string) *Repo {
	return &Repo{repoId: repoId, repoType: repoType, revision: revision}
}

func NewModelRepo(repoId string) *Repo {
	return NewRepo(repoId, Model)
}

func NewDatasetRepo(repoId string) *Repo {
	return NewRepo(repoId, Dataset)
}

func NewSpaceRepo(repoId string) *Repo {
	return NewRepo(repoId, Space)
}

func (r *Repo) Clone() *Repo {
	newRepo := *r
	return &newRepo
}

// FolderName  The normalized folder nameof the repo within the cache directory
func (r *Repo) FolderName() string {
	var prefix string
	switch r.repoType {
	case Model:
		prefix = "models"
	case Dataset:
		prefix = "datasets"
	case Space:
		prefix = "spaces"
	}
	result := fmt.Sprintf("%s--%s", prefix, r.repoId)
	result = strings.ReplaceAll(result, "/", "--")
	return result
}

func (r *Repo) Revision() string {
	return r.revision
}

func (r *Repo) Url() string {
	switch r.repoType {
	case Model:
		return r.repoId
	case Dataset:
		return fmt.Sprintf("datasets/%s", r.repoId)
	case Space:
		return fmt.Sprintf("spaces/%s", r.repoId)
	}
	return ""
}

func (r *Repo) UrlRevision() string {
	return strings.ReplaceAll(r.revision, "/", "%2F")
}

func (r *Repo) ApiUrl() string {
	var prefix string
	switch r.repoType {
	case Model:
		prefix = "models"
	case Dataset:
		prefix = "datasets"
	case Space:
		prefix = "spaces"
	}
	return fmt.Sprintf("%s/%s/revision/%s", prefix, r.repoId, r.UrlRevision())
}

type ApiBuilder struct {
	endpoint         string
	cache            *Cache
	urlTemplate      string
	token            string
	maxFiles         uint64
	chunkSize        uint64
	parallelFailures uint64
	maxRetries       uint64
	headers          http.Header
	transport        http.RoundTripper
	progress         bool
	// 使用总进度作为进度条
	totalProgress bool
	progressBar   Progress
}

func NewApiBuilder() (*ApiBuilder, error) {
	cache, err := DefaultCache()
	if err != nil {
		return nil, err
	}
	apiBuilder := &ApiBuilder{}
	return apiBuilder.FromCache(cache)
}

func (b *ApiBuilder) FromCache(cache *Cache) (*ApiBuilder, error) {
	endpoint := os.Getenv("HF_ENDPOINT")
	stagingMode := os.Getenv("HUGGINGFACE_CO_STAGING")
	if len(endpoint) == 0 {
		if len(stagingMode) > 0 && stagingMode == "true" {
			endpoint = "https://hub-ci.huggingface.co"
		} else {
			endpoint = "https://huggingface.co"
		}
	}

	token, err := cache.Token()
	if err != nil {
		return nil, err
	}

	return &ApiBuilder{
		endpoint:    "https://huggingface.co",
		urlTemplate: "{{.Endpoint}}/{{.RepoId}}/resolve/{{.Revision}}/{{.Filename}}",
		cache:       cache,
		token:       token,
		progress:    true,
	}, nil
}

func (b *ApiBuilder) WithEndpoint(endpoint string) *ApiBuilder {
	b.endpoint = endpoint
	return b
}

func (b *ApiBuilder) WithProgress(progress bool) *ApiBuilder {
	b.progress = progress
	return b
}

func (b *ApiBuilder) WithTotalProgressHandler(p Progress) *ApiBuilder {
	b.progress = true
	b.totalProgress = true
	b.progressBar = p
	return b
}

func (b *ApiBuilder) WithProgressHandler(p Progress) *ApiBuilder {
	b.progress = true
	b.progressBar = p
	return b
}

func (b *ApiBuilder) WithCacheDir(cacheDir string) *ApiBuilder {
	cache := NewCache(cacheDir, b.cache.resume)
	b.cache = cache
	return b
}

func (b *ApiBuilder) WithResume(resume bool) *ApiBuilder {
	cache := NewCache(b.cache.path, resume)
	b.cache = cache
	return b
}

func (b *ApiBuilder) WithToken(token string) *ApiBuilder {
	b.token = token
	return b
}

func (b *ApiBuilder) WithTransport(rt http.RoundTripper) *ApiBuilder {
	b.transport = rt
	return b
}

func (b *ApiBuilder) BuildHeaders() http.Header {
	headers := make(http.Header)
	userAgent := fmt.Sprintf("unkown/None; %s/%s; rust/unknown", "hf-hub", "v0.0.1")
	headers.Add("User-Agent", userAgent)
	if len(b.token) > 0 {
		headers.Add("Authorization", fmt.Sprintf("Bearer %s", b.token))
	}
	return headers
}

func (b *ApiBuilder) Build() *Api {
	headers := b.BuildHeaders()
	var rt http.RoundTripper
	if b.transport != nil {
		rt = b.transport
	} else {
		rt = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	noCDNRedirectClient := &http.Client{
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}

			if shouldRedirect(req.Response.StatusCode) {
				location := req.Response.Header.Get("Location")
				if location != "" && location[0] == '/' {
					baseURL := req.URL
					newURL, err := url.Parse(baseURL.Scheme + "://" + baseURL.Host + location)
					if err != nil {
						return err
					}
					req.URL = newURL
					return nil
				}
			}

			return http.ErrUseLastResponse
		},
	}
	client := &http.Client{Transport: rt}
	return &Api{
		endpoint:            b.endpoint,
		urlTemplate:         b.urlTemplate,
		cache:               b.cache,
		headers:             headers,
		client:              client,
		noCDNRedirectClient: noCDNRedirectClient,
		progress:            b.progress,
		totalProgress:       b.totalProgress,
		progressBar:         b.progressBar,
	}

}

type Metadata struct {
	commitHash string
	etag       string
	size       uint64
}

type Api struct {
	endpoint            string
	urlTemplate         string
	cache               *Cache
	headers             http.Header
	client              *http.Client
	noCDNRedirectClient *http.Client
	progress            bool
	totalProgress       bool
	progressBar         Progress
	meta                *Metadata
}

func NewApi() (*Api, error) {
	builder, err := NewApiBuilder()
	if err != nil {
		return nil, err
	}
	api := builder.Build()
	return api, nil
}

func (a *Api) metadata(ctx context.Context, url string) (*Metadata, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header = a.headers.Clone()
	req.Header.Add("Range", "bytes=0-0")

	res, err := a.noCDNRedirectClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	if res.StatusCode > 400 {
		return nil, fmt.Errorf("fail to get metadata, status code %d, status: %s", res.StatusCode, http.StatusText(res.StatusCode))
	}

	commitHash := res.Header.Get("x-repo-commit")
	if len(commitHash) == 0 {
		return nil, fmt.Errorf("miss header x-repo-commit for %s", url)
	}

	etag := res.Header.Get("x-linked-etag")
	if len(etag) == 0 {
		etag = res.Header.Get("etag")
		if len(etag) == 0 {
			return nil, fmt.Errorf("miss header etag for %s", url)
		}
	}
	etag = strings.ReplaceAll(etag, "\"", "")

	if 300 <= res.StatusCode && res.StatusCode <= 400 {
		location := res.Header.Get("Location")

		req, err = http.NewRequest(http.MethodGet, location, nil)
		if err != nil {
			return nil, err
		}

		req.Header = a.headers.Clone()
		req.Header.Add("Range", "bytes=0-0")
		res, err = a.client.Do(req)

		if err != nil {
			return nil, err
		}
	}

	contentRange := res.Header.Get("Content-Range")
	contentRanges := strings.Split(contentRange, "/")
	contentRange = contentRanges[len(contentRanges)-1]
	var size uint64
	if len(contentRange) == 0 {
		size, err = strconv.ParseUint(res.Header.Get("Content-Length"), 10, 64)
		if err != nil {
			return nil, err
		}
	} else {
		size, err = strconv.ParseUint(contentRange, 10, 64)
		if err != nil {
			return nil, err
		}

	}

	a.meta = &Metadata{
		commitHash: commitHash,
		etag:       etag,
		size:       size,
	}
	return a.meta, nil
}

func (a *Api) downloadTempFile(ctx context.Context, url string, progress Progress) (string, error) {
	filename, err := a.cache.TempPath(a.meta.etag)
	if err != nil {
		return "", err
	}

	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return "", err
	}
	defer file.Close()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req = req.WithContext(ctx)

	req.Header = a.headers.Clone()

	stat, _ := file.Stat()
	if stat.Size() > 0 {
		if a.meta.size > uint64(stat.Size()) {
			if !a.totalProgress {
				progress.Set64(stat.Size())
			}
			req.Header.Add("Range", fmt.Sprintf("bytes=%d-", stat.Size()))
		}
	}

	res, err := a.client.Do(req)
	if err != nil {
		return "", err
	}

	var mw io.Writer

	if progress != nil {
		mw = io.MultiWriter(file, progress)
	} else {
		mw = file
	}

	_, err = io.Copy(mw, res.Body)
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}

func (a *Api) Repo(rep *Repo) *ApiRepo {
	return NewApiRepo(a.Clone(), rep)
}

func (a *Api) Model(modelId string) *ApiRepo {
	return NewApiRepo(a.Clone(), NewModelRepo(modelId))
}

func (a *Api) Dataset(datasetId string) *ApiRepo {
	return NewApiRepo(a.Clone(), NewDatasetRepo(datasetId))
}

func (a *Api) Space(spaceId string) *ApiRepo {
	return NewApiRepo(a.Clone(), NewSpaceRepo(spaceId))
}

func (a *Api) Clone() *Api {
	newApi := *a
	newCache := *a.cache
	newClient := *a.client

	newApi.headers = newApi.headers.Clone()
	newApi.cache = &newCache
	newApi.client = &newClient
	return &newApi
}

type ApiRepo struct {
	api  *Api
	repo *Repo
}

func NewApiRepo(api *Api, rep *Repo) *ApiRepo {
	return &ApiRepo{
		api:  api,
		repo: rep,
	}
}

type UrlTemplateEntry struct {
	Endpoint string
	RepoId   string
	Revision string
	Filename string
}

func (r *ApiRepo) Url(filename string) (string, error) {
	t, err := template.New("test").Parse(r.api.urlTemplate)
	if err != nil {
		return "", nil
	}
	var buf bytes.Buffer
	//"{{.Endpoint}}/{{.RepoId}}/resolve/{{.Revision}}/{{.Filename}}",
	err = t.Execute(&buf, UrlTemplateEntry{
		Endpoint: r.api.endpoint,
		RepoId:   r.repo.Url(),
		Revision: r.repo.UrlRevision(),
		Filename: filename,
	})
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (r *ApiRepo) Get(ctx context.Context, filename string) (string, error) {
	path, err := r.api.cache.Repo(r.repo.Clone()).Get(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return r.Download(ctx, filename)
		}
		return "", err
	}
	return path, nil
}

func (r *ApiRepo) TotalSize(ctx context.Context) (int64, error) {
	rinfo, err := r.Info()
	if err != nil {
		return 0, err
	}
	total := 0
	for file := range rinfo.Siblings {
		filename := rinfo.Siblings[file].Rfilename
		apiUrl, err := r.Url(filename)
		if err != nil {
			return 0, err
		}

		metadata, err := r.api.metadata(ctx, apiUrl)
		if err != nil {
			return 0, err
		}
		total += int(metadata.size)
	}
	return int64(total), nil
}

func (r *ApiRepo) Download(ctx context.Context, filename string) (string, error) {
	apiUrl, err := r.Url(filename)
	if err != nil {
		return "", err
	}

	metadata, err := r.api.metadata(ctx, apiUrl)
	if err != nil {
		return "", err
	}

	blobPath := r.api.cache.Repo(r.repo.Clone()).BlobPath(metadata.etag)
	pointerPath := r.api.cache.Repo(r.repo.Clone()).PointerPath(metadata.commitHash)
	pointerPath = filepath.Join(pointerPath, filename)

	// if pointerPath exists, and blobPath size is same as metadata size, return pointerPath
	if _, err := os.Stat(pointerPath); err == nil {
		stat, err := os.Stat(blobPath)
		if err == nil && stat.Size() == int64(metadata.size) {
			absPointerPath, err := filepath.Abs(pointerPath)
			if err != nil {
				return "", err
			}
			if r.api.progress {
				if r.api.progressBar != nil {
					r.api.progressBar.Add(int64(metadata.size))
				}
			}
			return absPointerPath, nil
		}
	}

	err = os.MkdirAll(filepath.Dir(blobPath), os.ModePerm)
	if err != nil {
		return "", err
	}
	var bar Progress
	if r.api.progress {
		if r.api.progressBar != nil {
			bar = r.api.progressBar
		} else {
			var message string
			if len(filename) > 30 {
				message = fmt.Sprintf("..%s", filename[:30])
			} else {
				message = filename
			}
			b := progressbar.NewOptions64(
				int64(metadata.size),
				progressbar.OptionSetDescription(message),
				progressbar.OptionUseANSICodes(useANSICodes),
				progressbar.OptionSetPredictTime(true),
				progressbar.OptionShowBytes(true),
			)
			bar = &wrapperProgressBar{ProgressBar: b}
		}
	}

	tmpFilename, err := r.api.downloadTempFile(ctx, apiUrl, bar)
	if err != nil {
		return "", err
	}

	err = os.Rename(tmpFilename, blobPath)
	if err != nil {
		return "", err
	}

	err = os.MkdirAll(filepath.Dir(pointerPath), os.ModePerm)
	if err != nil {
		return "", err
	}

	err = symlinkOrRename(blobPath, pointerPath)
	if err != nil {
		return "", err
	}

	err = r.api.cache.Repo(r.repo.Clone()).CreateRef(metadata.commitHash)
	if err != nil {
		return "", err
	}

	absPointerPath, err := filepath.Abs(pointerPath)
	if err != nil {
		return "", err
	}

	return absPointerPath, nil
}

type Siblings struct {
	Rfilename string `json:"rfilename"`
}

type RepoInfo struct {
	Siblings []Siblings `json:"siblings"`
	Sha      string     `json:"sha"`
}

func (r *ApiRepo) Info() (*RepoInfo, error) {
	res, err := r.InfoRequest()
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var responseData RepoInfo
	err = json.NewDecoder(res.Body).Decode(&responseData)
	if err != nil {
		return nil, err
	}

	return &responseData, nil
}

func (r *ApiRepo) InfoRequest() (*http.Response, error) {
	apiUrl := fmt.Sprintf("%s/api/%s", r.api.endpoint, r.repo.ApiUrl())
	return r.api.client.Get(apiUrl)
}

func (r *ApiRepo) SnapshotDownload(ctx context.Context) error {
	totalsize, err := r.TotalSize(ctx)
	if err != nil {
		return err
	}
	if r.api.progressBar != nil {
		r.api.progressBar.Set64(totalsize)
	}
	rinfo, err := r.Info()
	if err != nil {
		return err
	}
	for _, sib := range rinfo.Siblings {
		_, err := r.Download(ctx, sib.Rfilename)
		if err != nil {
			return err
		}
	}
	return nil
}
