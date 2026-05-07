package starlarkext

import (
	"context"
	"fmt"
	"os"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	gogithttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v60/github"
	"go.starlark.net/starlark"
	"golang.org/x/oauth2"
)

// SetupVCSAPI registers git.* and github.* namespaces into the Starlark environment.
//
// git API:
//
//	git.clone(url="https://...", path="/tmp/repo")
//	git.open(path=".")
//	git.status(path=".")
//	git.add(path=".", files=".")
//	git.commit(path=".", message="fix: thing", author_name="", author_email="")
//	git.push(path=".", remote="origin", branch="main")
//	git.pull(path=".")
//	git.log(path=".", limit=10)
//
// github API (auth via GITHUB_TOKEN env var):
//
//	github.list_repos(owner="afterdarksys")
//	github.list_prs(repo="owner/name", state="open")
//	github.create_pr(repo="owner/name", title="t", body="b", head="feat", base="main")
//	github.merge_pr(repo="owner/name", number=42)
//	github.list_issues(repo="owner/name", state="open")
//	github.create_issue(repo="owner/name", title="t", body="b")
//	github.close_issue(repo="owner/name", number=7)
//	github.create_release(repo="owner/name", tag="v1.0.0", title="t", body="b")
//	github.list_workflows(repo="owner/name")
//	github.trigger_workflow(repo="owner/name", workflow_id="ci.yml", ref="main")
func SetupVCSAPI(env starlark.StringDict) {
	// git
	gitDict := starlark.NewDict(8)
	gitDict.SetKey(starlark.String("clone"), starlark.NewBuiltin("clone", gitClone))
	gitDict.SetKey(starlark.String("open"), starlark.NewBuiltin("open", gitOpen))
	gitDict.SetKey(starlark.String("status"), starlark.NewBuiltin("status", gitStatus))
	gitDict.SetKey(starlark.String("add"), starlark.NewBuiltin("add", gitAdd))
	gitDict.SetKey(starlark.String("commit"), starlark.NewBuiltin("commit", gitCommit))
	gitDict.SetKey(starlark.String("push"), starlark.NewBuiltin("push", gitPush))
	gitDict.SetKey(starlark.String("pull"), starlark.NewBuiltin("pull", gitPull))
	gitDict.SetKey(starlark.String("log"), starlark.NewBuiltin("log", gitLog))
	env["git"] = gitDict

	// github
	ghDict := starlark.NewDict(9)
	ghDict.SetKey(starlark.String("list_repos"), starlark.NewBuiltin("list_repos", ghListRepos))
	ghDict.SetKey(starlark.String("list_prs"), starlark.NewBuiltin("list_prs", ghListPRs))
	ghDict.SetKey(starlark.String("create_pr"), starlark.NewBuiltin("create_pr", ghCreatePR))
	ghDict.SetKey(starlark.String("merge_pr"), starlark.NewBuiltin("merge_pr", ghMergePR))
	ghDict.SetKey(starlark.String("list_issues"), starlark.NewBuiltin("list_issues", ghListIssues))
	ghDict.SetKey(starlark.String("create_issue"), starlark.NewBuiltin("create_issue", ghCreateIssue))
	ghDict.SetKey(starlark.String("close_issue"), starlark.NewBuiltin("close_issue", ghCloseIssue))
	ghDict.SetKey(starlark.String("create_release"), starlark.NewBuiltin("create_release", ghCreateRelease))
	ghDict.SetKey(starlark.String("list_workflows"), starlark.NewBuiltin("list_workflows", ghListWorkflows))
	ghDict.SetKey(starlark.String("trigger_workflow"), starlark.NewBuiltin("trigger_workflow", ghTriggerWorkflow))
	env["github"] = ghDict
}

// ── git helpers ───────────────────────────────────────────────────────────────

func gitHTTPAuth() *gogithttp.BasicAuth {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil
	}
	return &gogithttp.BasicAuth{Username: "token", Password: token}
}

func gitClone(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url, path string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &url, "path", &path); err != nil {
		return nil, err
	}
	opts := &gogit.CloneOptions{URL: url, Progress: os.Stdout}
	if auth := gitHTTPAuth(); auth != nil {
		opts.Auth = auth
	}
	if _, err := gogit.PlainClone(path, false, opts); err != nil {
		return nil, fmt.Errorf("git.clone: %v", err)
	}
	return starlark.String(path), nil
}

func gitOpen(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path?", &path); err != nil {
		return nil, err
	}
	if path == "" {
		var err error
		path, err = os.Getwd()
		if err != nil {
			return nil, err
		}
	}
	if _, err := gogit.PlainOpen(path); err != nil {
		return nil, fmt.Errorf("git.open: %v", err)
	}
	return starlark.String(path), nil
}

func gitStatus(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path?", &path); err != nil {
		return nil, err
	}
	if path == "" {
		path, _ = os.Getwd()
	}
	repo, err := gogit.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("git.status: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("git.status: %v", err)
	}
	status, err := wt.Status()
	if err != nil {
		return nil, fmt.Errorf("git.status: %v", err)
	}
	d := starlark.NewDict(len(status))
	for file, s := range status {
		d.SetKey(starlark.String(file), makeDict(
			"staging", string(s.Staging),
			"worktree", string(s.Worktree),
		))
	}
	return d, nil
}

func gitAdd(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, files string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path?", &path, "files?", &files); err != nil {
		return nil, err
	}
	if path == "" {
		path, _ = os.Getwd()
	}
	if files == "" {
		files = "."
	}
	repo, err := gogit.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("git.add: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("git.add: %v", err)
	}
	if _, err := wt.Add(files); err != nil {
		return nil, fmt.Errorf("git.add: %v", err)
	}
	return starlark.String("staged"), nil
}

func gitCommit(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, message, authorName, authorEmail string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"path?", &path,
		"message", &message,
		"author_name?", &authorName,
		"author_email?", &authorEmail,
	); err != nil {
		return nil, err
	}
	if path == "" {
		path, _ = os.Getwd()
	}
	if authorName == "" {
		authorName = "adssh"
	}
	if authorEmail == "" {
		authorEmail = "adssh@localhost"
	}
	repo, err := gogit.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("git.commit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("git.commit: %v", err)
	}
	hash, err := wt.Commit(message, &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  authorName,
			Email: authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("git.commit: %v", err)
	}
	return starlark.String(hash.String()), nil
}

func gitPush(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, remote string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path?", &path, "remote?", &remote); err != nil {
		return nil, err
	}
	if path == "" {
		path, _ = os.Getwd()
	}
	if remote == "" {
		remote = "origin"
	}
	repo, err := gogit.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("git.push: %v", err)
	}
	opts := &gogit.PushOptions{RemoteName: remote}
	if auth := gitHTTPAuth(); auth != nil {
		opts.Auth = auth
	}
	if err := repo.Push(opts); err != nil && err != gogit.NoErrAlreadyUpToDate {
		return nil, fmt.Errorf("git.push: %v", err)
	}
	return starlark.String("pushed"), nil
}

func gitPull(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path?", &path); err != nil {
		return nil, err
	}
	if path == "" {
		path, _ = os.Getwd()
	}
	repo, err := gogit.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("git.pull: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("git.pull: %v", err)
	}
	opts := &gogit.PullOptions{RemoteName: "origin"}
	if auth := gitHTTPAuth(); auth != nil {
		opts.Auth = auth
	}
	if err := wt.Pull(opts); err != nil && err != gogit.NoErrAlreadyUpToDate {
		return nil, fmt.Errorf("git.pull: %v", err)
	}
	return starlark.String("pulled"), nil
}

func gitLog(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	var limit int
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path?", &path, "limit?", &limit); err != nil {
		return nil, err
	}
	if path == "" {
		path, _ = os.Getwd()
	}
	if limit <= 0 {
		limit = 20
	}
	repo, err := gogit.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("git.log: %v", err)
	}
	iter, err := repo.Log(&gogit.LogOptions{})
	if err != nil {
		return nil, fmt.Errorf("git.log: %v", err)
	}
	defer iter.Close()

	var results []starlark.Value
	for i := 0; i < limit; i++ {
		commit, err := iter.Next()
		if err != nil {
			break
		}
		results = append(results, makeDict(
			"hash", commit.Hash.String(),
			"message", commit.Message,
			"author", commit.Author.Name,
			"email", commit.Author.Email,
			"timestamp", commit.Author.When.Format(time.RFC3339),
		))
	}
	return starlark.NewList(results), nil
}

// ── GitHub helpers ────────────────────────────────────────────────────────────

func ghClient() (*github.Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable is not set")
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return github.NewClient(oauth2.NewClient(context.Background(), ts)), nil
}

func ghSplitRepo(repo string) (string, string, error) {
	parts := splitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("repo must be in 'owner/name' format, got: %s", repo)
	}
	return parts[0], parts[1], nil
}

func splitN(s, sep string, n int) []string {
	var result []string
	for i := 0; i < n-1; i++ {
		idx := indexOf(s, sep)
		if idx < 0 {
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return append(result, s)
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func ghListRepos(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var owner string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "owner?", &owner); err != nil {
		return nil, err
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	var repos []*github.Repository
	if owner == "" {
		repos, _, err = client.Repositories.List(ctx, "", nil)
	} else {
		repos, _, err = client.Repositories.List(ctx, owner, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("github.list_repos: %v", err)
	}
	var results []starlark.Value
	for _, r := range repos {
		results = append(results, makeDict(
			"name", r.GetFullName(),
			"description", r.GetDescription(),
			"private", r.GetPrivate(),
			"stars", int64(r.GetStargazersCount()),
			"language", r.GetLanguage(),
			"url", r.GetHTMLURL(),
		))
	}
	return starlark.NewList(results), nil
}

func ghListPRs(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo, state string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "repo", &repo, "state?", &state); err != nil {
		return nil, err
	}
	owner, name, err := ghSplitRepo(repo)
	if err != nil {
		return nil, err
	}
	if state == "" {
		state = "open"
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	prs, _, err := client.PullRequests.List(context.Background(), owner, name, &github.PullRequestListOptions{State: state})
	if err != nil {
		return nil, fmt.Errorf("github.list_prs: %v", err)
	}
	var results []starlark.Value
	for _, pr := range prs {
		results = append(results, makeDict(
			"number", int64(pr.GetNumber()),
			"title", pr.GetTitle(),
			"state", pr.GetState(),
			"head", pr.GetHead().GetRef(),
			"base", pr.GetBase().GetRef(),
			"author", pr.GetUser().GetLogin(),
			"url", pr.GetHTMLURL(),
		))
	}
	return starlark.NewList(results), nil
}

func ghCreatePR(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo, title, body, head, base string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"repo", &repo, "title", &title, "body?", &body, "head", &head, "base", &base,
	); err != nil {
		return nil, err
	}
	owner, name, err := ghSplitRepo(repo)
	if err != nil {
		return nil, err
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	pr, _, err := client.PullRequests.Create(context.Background(), owner, name, &github.NewPullRequest{
		Title: github.String(title),
		Body:  github.String(body),
		Head:  github.String(head),
		Base:  github.String(base),
	})
	if err != nil {
		return nil, fmt.Errorf("github.create_pr: %v", err)
	}
	return makeDict("number", int64(pr.GetNumber()), "url", pr.GetHTMLURL()), nil
}

func ghMergePR(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo string
	var number int
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "repo", &repo, "number", &number); err != nil {
		return nil, err
	}
	owner, name, err := ghSplitRepo(repo)
	if err != nil {
		return nil, err
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	result, _, err := client.PullRequests.Merge(context.Background(), owner, name, number, "", nil)
	if err != nil {
		return nil, fmt.Errorf("github.merge_pr: %v", err)
	}
	return makeDict("merged", result.GetMerged(), "sha", result.GetSHA()), nil
}

func ghListIssues(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo, state string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "repo", &repo, "state?", &state); err != nil {
		return nil, err
	}
	owner, name, err := ghSplitRepo(repo)
	if err != nil {
		return nil, err
	}
	if state == "" {
		state = "open"
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	issues, _, err := client.Issues.ListByRepo(context.Background(), owner, name, &github.IssueListByRepoOptions{State: state})
	if err != nil {
		return nil, fmt.Errorf("github.list_issues: %v", err)
	}
	var results []starlark.Value
	for _, issue := range issues {
		if issue.PullRequestLinks != nil {
			continue // skip PRs
		}
		results = append(results, makeDict(
			"number", int64(issue.GetNumber()),
			"title", issue.GetTitle(),
			"state", issue.GetState(),
			"author", issue.GetUser().GetLogin(),
			"url", issue.GetHTMLURL(),
		))
	}
	return starlark.NewList(results), nil
}

func ghCreateIssue(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo, title, body string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "repo", &repo, "title", &title, "body?", &body); err != nil {
		return nil, err
	}
	owner, name, err := ghSplitRepo(repo)
	if err != nil {
		return nil, err
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	issue, _, err := client.Issues.Create(context.Background(), owner, name, &github.IssueRequest{
		Title: github.String(title),
		Body:  github.String(body),
	})
	if err != nil {
		return nil, fmt.Errorf("github.create_issue: %v", err)
	}
	return makeDict("number", int64(issue.GetNumber()), "url", issue.GetHTMLURL()), nil
}

func ghCloseIssue(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo string
	var number int
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "repo", &repo, "number", &number); err != nil {
		return nil, err
	}
	owner, name, err := ghSplitRepo(repo)
	if err != nil {
		return nil, err
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	closed := "closed"
	_, _, err = client.Issues.Edit(context.Background(), owner, name, number, &github.IssueRequest{State: &closed})
	if err != nil {
		return nil, fmt.Errorf("github.close_issue: %v", err)
	}
	return starlark.String("closed"), nil
}

func ghCreateRelease(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo, tag, title, body string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "repo", &repo, "tag", &tag, "title", &title, "body?", &body); err != nil {
		return nil, err
	}
	owner, name, err := ghSplitRepo(repo)
	if err != nil {
		return nil, err
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	release, _, err := client.Repositories.CreateRelease(context.Background(), owner, name, &github.RepositoryRelease{
		TagName: github.String(tag),
		Name:    github.String(title),
		Body:    github.String(body),
	})
	if err != nil {
		return nil, fmt.Errorf("github.create_release: %v", err)
	}
	return makeDict("id", release.GetID(), "url", release.GetHTMLURL()), nil
}

func ghListWorkflows(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "repo", &repo); err != nil {
		return nil, err
	}
	owner, name, err := ghSplitRepo(repo)
	if err != nil {
		return nil, err
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	wfs, _, err := client.Actions.ListWorkflows(context.Background(), owner, name, nil)
	if err != nil {
		return nil, fmt.Errorf("github.list_workflows: %v", err)
	}
	var results []starlark.Value
	for _, wf := range wfs.Workflows {
		results = append(results, makeDict(
			"id", wf.GetID(),
			"name", wf.GetName(),
			"state", wf.GetState(),
			"path", wf.GetPath(),
		))
	}
	return starlark.NewList(results), nil
}

func ghTriggerWorkflow(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo, workflowID, ref string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "repo", &repo, "workflow_id", &workflowID, "ref?", &ref); err != nil {
		return nil, err
	}
	if ref == "" {
		ref = "main"
	}
	owner, name, err := ghSplitRepo(repo)
	if err != nil {
		return nil, err
	}
	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	_, err = client.Actions.CreateWorkflowDispatchEventByFileName(context.Background(), owner, name, workflowID, github.CreateWorkflowDispatchEventRequest{
		Ref: ref,
	})
	if err != nil {
		return nil, fmt.Errorf("github.trigger_workflow: %v", err)
	}
	return starlark.String("triggered"), nil
}
