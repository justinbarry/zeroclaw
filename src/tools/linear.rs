use super::traits::{Tool, ToolResult};
use crate::security::{SecurityPolicy, policy::ToolOperation};
use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use std::sync::Arc;

const DEFAULT_PAGE_SIZE: u64 = 10;
const MAX_PAGE_SIZE: u64 = 50;
const ISSUE_LOOKUP_LIMIT: u64 = 10;
const MAX_ERROR_BODY_CHARS: usize = 500;

const SEARCH_ISSUES_QUERY: &str = r#"
query SearchIssues(
  $term: String!,
  $first: Int!,
  $teamId: String,
  $includeComments: Boolean,
  $includeArchived: Boolean
) {
  searchIssues(
    term: $term,
    first: $first,
    teamId: $teamId,
    includeComments: $includeComments,
    includeArchived: $includeArchived
  ) {
    nodes {
      id
      identifier
      title
      priority
      url
      updatedAt
      team { id key name }
      state { id name type }
      assignee { id name email }
      project { id name }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"#;

const GET_ISSUE_QUERY: &str = r#"
query GetIssue($id: String!) {
  issue(id: $id) {
    id
    identifier
    title
    description
    priority
    estimate
    dueDate
    url
    createdAt
    updatedAt
    team { id key name }
    state { id name type }
    assignee { id name email }
    project { id name }
    labels {
      nodes { id name color }
    }
  }
}
"#;

const LIST_COMMENTS_QUERY: &str = r#"
query ListComments($id: String!, $first: Int!) {
  issue(id: $id) {
    id
    identifier
    title
    comments(first: $first) {
      nodes {
        id
        body
        url
        createdAt
        updatedAt
        parentId
        resolvedAt
        user { id name email }
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}
"#;

const GET_PROJECT_QUERY: &str = r#"
query GetProject($id: String!) {
  project(id: $id) {
    id
    name
    description
    slugId
    icon
    color
    startDate
    targetDate
    priority
    url
    lead { id name displayName email active url }
    teams {
      nodes { id key name displayName description }
    }
    members {
      nodes { id name displayName email active url }
    }
    labels {
      nodes { id name color }
    }
  }
}
"#;

const GET_DOCUMENT_QUERY: &str = r#"
query GetDocument($id: String!) {
  document(id: $id) {
    id
    title
    summary
    content
    icon
    color
    slugId
    sortOrder
    url
    createdAt
    updatedAt
    creator { id name displayName email active url }
    updatedBy { id name displayName email active url }
    project { id name description slugId icon color targetDate startDate priority url }
  }
}
"#;

const LIST_PROJECT_DOCUMENTS_QUERY: &str = r#"
query ListProjectDocuments($id: String!, $first: Int!, $includeArchived: Boolean!) {
  project(id: $id) {
    id
    name
    documents(first: $first, includeArchived: $includeArchived) {
      nodes {
        id
        title
        summary
        icon
        color
        slugId
        sortOrder
        url
        createdAt
        updatedAt
        creator { id name displayName email active url }
        updatedBy { id name displayName email active url }
        project { id name description slugId icon color targetDate startDate priority url }
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}
"#;

const SEARCH_PROJECTS_QUERY: &str = r#"
query SearchProjects($term: String!, $first: Int!) {
  searchProjects(term: $term, first: $first) {
    nodes {
      id
      name
      description
      slugId
      icon
      color
      startDate
      targetDate
      priority
      url
      lead { id name displayName email active url }
      teams {
        nodes { id key name displayName description }
      }
      labels {
        nodes { id name color }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"#;

const LIST_TEAMS_QUERY: &str = r#"
query ListTeams($first: Int!) {
  teams(first: $first) {
    nodes {
      id
      key
      name
      displayName
      description
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"#;

const LIST_USERS_QUERY: &str = r#"
query ListUsers($first: Int!, $includeDisabled: Boolean!) {
  users(first: $first, includeDisabled: $includeDisabled) {
    nodes {
      id
      name
      displayName
      email
      active
      url
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"#;

const LIST_WORKFLOW_STATES_QUERY: &str = r#"
query ListWorkflowStates($first: Int!) {
  workflowStates(first: $first) {
    nodes {
      id
      name
      color
      description
      position
      type
      team { id key name displayName description }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"#;

const CREATE_COMMENT_MUTATION: &str = r#"
mutation CreateComment($input: CommentCreateInput!) {
  commentCreate(input: $input) {
    success
    comment {
      id
      body
      url
      createdAt
      updatedAt
      issue {
        id
        identifier
        title
      }
      user { id name email }
    }
  }
}
"#;

const CREATE_ISSUE_MUTATION: &str = r#"
mutation CreateIssue($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue {
      id
      identifier
      title
      description
      priority
      estimate
      dueDate
      url
      createdAt
      updatedAt
      team { id key name displayName description }
      state { id name color description position type team { id key name } }
      assignee { id name displayName email active url }
      project { id name description slugId icon color targetDate startDate priority url }
      labels {
        nodes { id name color }
      }
    }
  }
}
"#;

const UPDATE_ISSUE_MUTATION: &str = r#"
mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
  issueUpdate(id: $id, input: $input) {
    success
    issue {
      id
      identifier
      title
      description
      priority
      estimate
      dueDate
      url
      updatedAt
      team { id key name }
      state { id name type }
      assignee { id name email }
      project { id name }
      labels {
        nodes { id name color }
      }
    }
  }
}
"#;

const UPDATE_PROJECT_MUTATION: &str = r#"
mutation UpdateProject($id: String!, $input: ProjectUpdateInput!) {
  projectUpdate(id: $id, input: $input) {
    success
    project {
      id
      name
      description
      slugId
      icon
      color
      startDate
      targetDate
      priority
      url
      lead { id name displayName email active url }
      teams {
        nodes { id key name displayName description }
      }
      members {
        nodes { id name displayName email active url }
      }
      labels {
        nodes { id name color }
      }
    }
  }
}
"#;

const CREATE_DOCUMENT_MUTATION: &str = r#"
mutation CreateDocument($input: DocumentCreateInput!) {
  documentCreate(input: $input) {
    success
    document {
      id
      title
      summary
      content
      icon
      color
      slugId
      sortOrder
      url
      createdAt
      updatedAt
      creator { id name displayName email active url }
      updatedBy { id name displayName email active url }
      project { id name description slugId icon color targetDate startDate priority url }
    }
  }
}
"#;

const UPDATE_DOCUMENT_MUTATION: &str = r#"
mutation UpdateDocument($id: String!, $input: DocumentUpdateInput!) {
  documentUpdate(id: $id, input: $input) {
    success
    document {
      id
      title
      summary
      content
      icon
      color
      slugId
      sortOrder
      url
      createdAt
      updatedAt
      creator { id name displayName email active url }
      updatedBy { id name displayName email active url }
      project { id name description slugId icon color targetDate startDate priority url }
    }
  }
}
"#;

pub struct LinearTool {
    api_url: String,
    api_key: String,
    allowed_actions: Vec<String>,
    http: reqwest::Client,
    security: Arc<SecurityPolicy>,
}

impl LinearTool {
    pub fn new(
        api_url: String,
        api_key: String,
        allowed_actions: Vec<String>,
        security: Arc<SecurityPolicy>,
        timeout_secs: u64,
    ) -> Self {
        Self {
            api_url,
            api_key,
            allowed_actions,
            http: crate::config::build_runtime_proxy_client_with_timeouts(
                "tool.linear",
                timeout_secs,
                10,
            ),
            security,
        }
    }

    fn is_action_allowed(&self, action: &str) -> bool {
        self.allowed_actions.iter().any(|a| a == action)
    }

    async fn graphql<T: DeserializeOwned>(
        &self,
        query: &str,
        variables: Value,
        operation_name: Option<&str>,
    ) -> anyhow::Result<T> {
        let mut body = json!({
            "query": query,
            "variables": variables,
        });
        if let Some(operation_name) = operation_name {
            body["operationName"] = json!(operation_name);
        }

        let response = self
            .http
            .post(&self.api_url)
            // Linear API keys use Authorization without a Bearer prefix.
            .header("Authorization", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Linear request failed: {e}"))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Linear request failed ({status}): {}",
                crate::util::truncate_with_ellipsis(&body, MAX_ERROR_BODY_CHARS)
            );
        }

        let payload: GraphQlResponse<T> = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse Linear response: {e}"))?;

        if let Some(errors) = payload.errors.filter(|errors| !errors.is_empty()) {
            let messages = errors
                .iter()
                .map(|error| error.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            anyhow::bail!("Linear GraphQL error: {messages}");
        }

        payload
            .data
            .ok_or_else(|| anyhow::anyhow!("Linear response missing data"))
    }

    async fn run_graphql_document(
        &self,
        args: &Value,
        mutation_mode: bool,
    ) -> anyhow::Result<ToolResult> {
        let document = trimmed(args.get("query").and_then(Value::as_str))
            .ok_or_else(|| anyhow::anyhow!("Provide a non-empty GraphQL document in query"))?;
        let variables = args.get("variables").cloned().unwrap_or_else(|| json!({}));
        if !variables.is_object() {
            anyhow::bail!("variables must be a JSON object when provided");
        }
        let operation_name = trimmed(args.get("operation_name").and_then(Value::as_str));

        match classify_graphql_document(document) {
            GraphQlDocumentKind::Mutation if !mutation_mode => {
                anyhow::bail!(
                    "graphql_query only accepts query documents. Use graphql_mutation for mutation operations."
                );
            }
            GraphQlDocumentKind::Subscription => {
                anyhow::bail!("Linear subscriptions are not supported by this tool");
            }
            GraphQlDocumentKind::Unknown if mutation_mode => {
                anyhow::bail!(
                    "graphql_mutation requires a GraphQL mutation document starting with the 'mutation' keyword"
                );
            }
            GraphQlDocumentKind::QueryLike if mutation_mode => {
                anyhow::bail!(
                    "graphql_mutation requires a mutation document. Use graphql_query for queries."
                );
            }
            _ => {}
        }

        let data = self
            .graphql::<Value>(document, variables, operation_name)
            .await?;

        json_tool_result(&data)
    }

    async fn resolve_issue_id(
        &self,
        issue_id: Option<&str>,
        issue_ref: Option<&str>,
    ) -> anyhow::Result<String> {
        if let Some(id) = trimmed(issue_id) {
            return Ok(id.to_string());
        }

        let issue_ref =
            trimmed(issue_ref).ok_or_else(|| anyhow::anyhow!("Provide issue_id or issue_ref"))?;

        let data = self
            .graphql::<SearchIssuesData>(
                SEARCH_ISSUES_QUERY,
                json!({
                    "term": issue_ref,
                    "first": ISSUE_LOOKUP_LIMIT,
                    "teamId": Value::Null,
                    "includeComments": false,
                    "includeArchived": false,
                }),
                None,
            )
            .await?;

        if let Some(exact_match) = data
            .search_issues
            .nodes
            .iter()
            .find(|issue| issue.identifier.eq_ignore_ascii_case(issue_ref))
        {
            return Ok(exact_match.id.clone());
        }

        match data.search_issues.nodes.as_slice() {
            [] => anyhow::bail!("Linear issue not found for reference '{issue_ref}'"),
            [single] => Ok(single.id.clone()),
            many => {
                let candidates = many
                    .iter()
                    .take(5)
                    .map(|issue| format!("{} ({})", issue.identifier, issue.title))
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::bail!(
                    "Linear issue reference '{issue_ref}' matched multiple issues: {candidates}. Pass issue_id for an exact target."
                )
            }
        }
    }

    async fn get_issue(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let issue_id = self
            .resolve_issue_id(
                args.get("issue_id").and_then(Value::as_str),
                args.get("issue_ref").and_then(Value::as_str),
            )
            .await?;

        let data = self
            .graphql::<GetIssueData>(GET_ISSUE_QUERY, json!({ "id": issue_id }), None)
            .await?;

        let Some(issue) = data.issue else {
            anyhow::bail!("Linear issue was not found");
        };

        json_tool_result(&issue)
    }

    async fn search_issues(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let term = trimmed(args.get("term").and_then(Value::as_str))
            .ok_or_else(|| anyhow::anyhow!("search_issues requires term"))?;
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64));
        let team_id = args.get("team_id").and_then(Value::as_str);
        let include_comments = args
            .get("include_comments")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let include_archived = args
            .get("include_archived")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let data = self
            .graphql::<SearchIssuesData>(
                SEARCH_ISSUES_QUERY,
                json!({
                    "term": term,
                    "first": limit,
                    "teamId": team_id,
                    "includeComments": include_comments,
                    "includeArchived": include_archived,
                }),
                None,
            )
            .await?;

        json_tool_result(&json!({
            "issues": data.search_issues.nodes,
            "page_info": data.search_issues.page_info,
        }))
    }

    async fn list_comments(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let issue_id = self
            .resolve_issue_id(
                args.get("issue_id").and_then(Value::as_str),
                args.get("issue_ref").and_then(Value::as_str),
            )
            .await?;
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64));

        let data = self
            .graphql::<ListCommentsData>(
                LIST_COMMENTS_QUERY,
                json!({
                    "id": issue_id,
                    "first": limit,
                }),
                None,
            )
            .await?;

        let Some(issue) = data.issue else {
            anyhow::bail!("Linear issue was not found");
        };

        json_tool_result(&json!({
            "issue": {
                "id": issue.id,
                "identifier": issue.identifier,
                "title": issue.title,
            },
            "comments": issue.comments.nodes,
            "page_info": issue.comments.page_info,
        }))
    }

    async fn create_comment(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let issue_id = self
            .resolve_issue_id(
                args.get("issue_id").and_then(Value::as_str),
                args.get("issue_ref").and_then(Value::as_str),
            )
            .await?;
        let body = trimmed(args.get("body").and_then(Value::as_str))
            .ok_or_else(|| anyhow::anyhow!("create_comment requires a non-empty body"))?;

        let data = self
            .graphql::<CommentCreateData>(
                CREATE_COMMENT_MUTATION,
                json!({
                    "input": {
                        "issueId": issue_id,
                        "body": body,
                    }
                }),
                None,
            )
            .await?;

        if !data.comment_create.success {
            anyhow::bail!("Linear create_comment returned success=false");
        }

        json_tool_result(&data.comment_create.comment)
    }

    async fn create_issue(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let input = build_issue_create_input(args)?;

        let data = self
            .graphql::<IssueCreateData>(
                CREATE_ISSUE_MUTATION,
                json!({
                    "input": input,
                }),
                None,
            )
            .await?;

        if !data.issue_create.success {
            anyhow::bail!("Linear create_issue returned success=false");
        }

        let Some(issue) = data.issue_create.issue else {
            anyhow::bail!("Linear create_issue succeeded but returned no issue payload");
        };

        json_tool_result(&issue)
    }

    async fn update_issue(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let issue_id = self
            .resolve_issue_id(
                args.get("issue_id").and_then(Value::as_str),
                args.get("issue_ref").and_then(Value::as_str),
            )
            .await?;
        let input = build_issue_update_input(args)?;

        let data = self
            .graphql::<IssueUpdateData>(
                UPDATE_ISSUE_MUTATION,
                json!({
                    "id": issue_id,
                    "input": input,
                }),
                None,
            )
            .await?;

        if !data.issue_update.success {
            anyhow::bail!("Linear update_issue returned success=false");
        }

        let Some(issue) = data.issue_update.issue else {
            anyhow::bail!("Linear update_issue succeeded but returned no issue payload");
        };

        json_tool_result(&issue)
    }

    async fn get_project(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let project_id = trimmed(args.get("project_id").and_then(Value::as_str))
            .ok_or_else(|| anyhow::anyhow!("get_project requires project_id"))?;

        let data = self
            .graphql::<GetProjectData>(GET_PROJECT_QUERY, json!({ "id": project_id }), None)
            .await?;

        let Some(project) = data.project else {
            anyhow::bail!("Linear project was not found");
        };

        json_tool_result(&project)
    }

    async fn get_document(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let document_id = trimmed(args.get("document_id").and_then(Value::as_str))
            .ok_or_else(|| anyhow::anyhow!("get_document requires document_id"))?;

        let data = self
            .graphql::<GetDocumentData>(GET_DOCUMENT_QUERY, json!({ "id": document_id }), None)
            .await?;

        let Some(document) = data.document else {
            anyhow::bail!("Linear document was not found");
        };

        json_tool_result(&document)
    }

    async fn list_project_documents(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let project_id = trimmed(args.get("project_id").and_then(Value::as_str))
            .ok_or_else(|| anyhow::anyhow!("list_project_documents requires project_id"))?;
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64));
        let include_archived = args
            .get("include_archived")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let data = self
            .graphql::<ListProjectDocumentsData>(
                LIST_PROJECT_DOCUMENTS_QUERY,
                json!({
                    "id": project_id,
                    "first": limit,
                    "includeArchived": include_archived,
                }),
                None,
            )
            .await?;

        let Some(project) = data.project else {
            anyhow::bail!("Linear project was not found");
        };

        json_tool_result(&json!({
            "project": {
                "id": project.id,
                "name": project.name,
            },
            "documents": project.documents.nodes,
            "page_info": project.documents.page_info,
        }))
    }

    async fn search_projects(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let term = trimmed(args.get("term").and_then(Value::as_str))
            .ok_or_else(|| anyhow::anyhow!("search_projects requires term"))?;
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64));

        let data = self
            .graphql::<SearchProjectsData>(
                SEARCH_PROJECTS_QUERY,
                json!({
                    "term": term,
                    "first": limit,
                }),
                None,
            )
            .await?;

        json_tool_result(&json!({
            "projects": data.search_projects.nodes,
            "page_info": data.search_projects.page_info,
        }))
    }

    async fn list_teams(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64));

        let data = self
            .graphql::<ListTeamsData>(LIST_TEAMS_QUERY, json!({ "first": limit }), None)
            .await?;

        json_tool_result(&json!({
            "teams": data.teams.nodes,
            "page_info": data.teams.page_info,
        }))
    }

    async fn list_users(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64));
        let include_disabled = args
            .get("include_disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let data = self
            .graphql::<ListUsersData>(
                LIST_USERS_QUERY,
                json!({
                    "first": limit,
                    "includeDisabled": include_disabled,
                }),
                None,
            )
            .await?;

        json_tool_result(&json!({
            "users": data.users.nodes,
            "page_info": data.users.page_info,
        }))
    }

    async fn list_workflow_states(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64));

        let data = self
            .graphql::<ListWorkflowStatesData>(
                LIST_WORKFLOW_STATES_QUERY,
                json!({ "first": limit }),
                None,
            )
            .await?;

        json_tool_result(&json!({
            "workflow_states": data.workflow_states.nodes,
            "page_info": data.workflow_states.page_info,
        }))
    }

    async fn create_document(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let input = build_document_create_input(args)?;

        let data = self
            .graphql::<DocumentCreateData>(
                CREATE_DOCUMENT_MUTATION,
                json!({
                    "input": input,
                }),
                None,
            )
            .await?;

        if !data.document_create.success {
            anyhow::bail!("Linear create_document returned success=false");
        }

        let Some(document) = data.document_create.document else {
            anyhow::bail!("Linear create_document succeeded but returned no document payload");
        };

        json_tool_result(&document)
    }

    async fn update_project(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let project_id = trimmed(args.get("project_id").and_then(Value::as_str))
            .ok_or_else(|| anyhow::anyhow!("update_project requires project_id"))?;
        let input = build_project_update_input(args)?;

        let data = self
            .graphql::<ProjectUpdateData>(
                UPDATE_PROJECT_MUTATION,
                json!({
                    "id": project_id,
                    "input": input,
                }),
                None,
            )
            .await?;

        if !data.project_update.success {
            anyhow::bail!("Linear update_project returned success=false");
        }

        let Some(project) = data.project_update.project else {
            anyhow::bail!("Linear update_project succeeded but returned no project payload");
        };

        json_tool_result(&project)
    }

    async fn update_document(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let document_id = trimmed(args.get("document_id").and_then(Value::as_str))
            .ok_or_else(|| anyhow::anyhow!("update_document requires document_id"))?;
        let input = build_document_update_input(args)?;

        let data = self
            .graphql::<DocumentUpdateData>(
                UPDATE_DOCUMENT_MUTATION,
                json!({
                    "id": document_id,
                    "input": input,
                }),
                None,
            )
            .await?;

        if !data.document_update.success {
            anyhow::bail!("Linear update_document returned success=false");
        }

        let Some(document) = data.document_update.document else {
            anyhow::bail!("Linear update_document succeeded but returned no document payload");
        };

        json_tool_result(&document)
    }
}

#[async_trait]
impl Tool for LinearTool {
    fn name(&self) -> &str {
        "linear"
    }

    fn description(&self) -> &str {
        "Interact with Linear: use curated issue/comment actions or run arbitrary GraphQL queries and mutations."
    }

    fn parameters_schema(&self) -> Value {
        serde_json::from_str(
            r#"{
              "type": "object",
              "properties": {
                "action": {
                  "type": "string",
                  "enum": [
                    "get_issue",
                    "search_issues",
                    "list_comments",
                    "create_comment",
                    "create_issue",
                    "update_issue",
                    "get_project",
                    "get_document",
                    "list_project_documents",
                    "search_projects",
                    "list_teams",
                    "list_users",
                    "list_workflow_states",
                    "create_document",
                    "update_project",
                    "update_document",
                    "graphql_query",
                    "graphql_mutation"
                  ],
                  "description": "The Linear action to perform"
                },
                "issue_id": {
                  "type": "string",
                  "description": "Linear issue UUID. Preferred when known."
                },
                "issue_ref": {
                  "type": "string",
                  "description": "Issue reference to resolve via Linear search, usually an identifier like ENG-123."
                },
                "term": {
                  "type": "string",
                  "description": "Full-text issue or project search term."
                },
                "team_id": {
                  "type": "string",
                  "description": "Linear team UUID used by search_issues or required by create_issue."
                },
                "limit": {
                  "type": "integer",
                  "description": "Maximum number of results to return for list and search actions (default 10, max 50)."
                },
                "include_comments": {
                  "type": "boolean",
                  "description": "Include comment hits in search_issues."
                },
                "include_archived": {
                  "type": "boolean",
                  "description": "Include archived issues in search_issues."
                },
                "include_disabled": {
                  "type": "boolean",
                  "description": "Include disabled users in list_users."
                },
                "body": {
                  "type": "string",
                  "description": "Comment body for create_comment."
                },
                "query": {
                  "type": "string",
                  "description": "Raw GraphQL document for graphql_query or graphql_mutation."
                },
                "variables": {
                  "type": "object",
                  "description": "Variables object for graphql_query or graphql_mutation."
                },
                "operation_name": {
                  "type": "string",
                  "description": "Optional GraphQL operation name for graphql_query or graphql_mutation."
                },
                "title": {
                  "type": "string",
                  "description": "Issue title for create_issue or a new title for update_issue."
                },
                "name": {
                  "type": "string",
                  "description": "New project name for update_project."
                },
                "description": {
                  "type": "string",
                  "description": "Markdown description for create_issue, update_issue, or update_project."
                },
                "state_id": {
                  "type": "string",
                  "description": "Workflow state UUID for create_issue or update_issue."
                },
                "assignee_id": {
                  "type": "string",
                  "description": "Assignee user UUID for create_issue or update_issue."
                },
                "priority": {
                  "type": "integer",
                  "description": "Priority for create_issue, update_issue, or update_project (Linear uses integer priorities)."
                },
                "estimate": {
                  "type": "integer",
                  "description": "Estimate value for create_issue or update_issue."
                },
                "due_date": {
                  "type": "string",
                  "description": "Due date for create_issue or update_issue in YYYY-MM-DD format."
                },
                "project_id": {
                  "type": "string",
                  "description": "Project UUID for get_project, list_project_documents, create_document, update_project, create_issue, or update_issue."
                },
                "document_id": {
                  "type": "string",
                  "description": "Linear document UUID for get_document or update_document."
                },
                "team_update_id": {
                  "type": "string",
                  "description": "Team UUID for update_issue. Named team_update_id to avoid confusion with search_issues.team_id."
                },
                "cycle_id": {
                  "type": "string",
                  "description": "Cycle UUID for create_issue or update_issue."
                },
                "parent_id": {
                  "type": "string",
                  "description": "Parent issue UUID for create_issue or update_issue."
                },
                "label_ids": {
                  "type": "array",
                  "items": { "type": "string" },
                  "description": "Replace label IDs for create_issue, update_issue, or update_project."
                },
                "added_label_ids": {
                  "type": "array",
                  "items": { "type": "string" },
                  "description": "Add these label UUIDs to the issue."
                },
                "removed_label_ids": {
                  "type": "array",
                  "items": { "type": "string" },
                  "description": "Remove these label UUIDs from the issue."
                },
                "content": {
                  "type": "string",
                  "description": "Long-form markdown content for create_document, update_document, or update_project."
                },
                "icon": {
                  "type": "string",
                  "description": "Icon for create_document, update_document, or update_project."
                },
                "color": {
                  "type": "string",
                  "description": "Color for create_document, update_document, or update_project."
                },
                "status_id": {
                  "type": "string",
                  "description": "Project status UUID for update_project."
                },
                "lead_id": {
                  "type": "string",
                  "description": "Project lead user UUID for update_project."
                },
                "start_date": {
                  "type": "string",
                  "description": "Start date for update_project in YYYY-MM-DD format."
                },
                "target_date": {
                  "type": "string",
                  "description": "Target date for update_project in YYYY-MM-DD format."
                },
                "team_ids": {
                  "type": "array",
                  "items": { "type": "string" },
                  "description": "Replace project teams with these UUIDs for update_project."
                },
                "member_ids": {
                  "type": "array",
                  "items": { "type": "string" },
                  "description": "Replace project members with these UUIDs for update_project."
                },
                "sort_order": {
                  "type": "number",
                  "description": "Document sort order for create_document or update_document."
                }
              },
              "required": ["action"]
            }"#,
        )
        .expect("linear tool schema must be valid JSON")
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let action = match args.get("action").and_then(Value::as_str) {
            Some(action) => action,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing required parameter: action".into()),
                });
            }
        };

        if !matches!(
            action,
            "get_issue"
                | "search_issues"
                | "list_comments"
                | "create_comment"
                | "create_issue"
                | "update_issue"
                | "get_project"
                | "get_document"
                | "list_project_documents"
                | "search_projects"
                | "list_teams"
                | "list_users"
                | "list_workflow_states"
                | "create_document"
                | "update_project"
                | "update_document"
                | "graphql_query"
                | "graphql_mutation"
        ) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unknown action: '{action}'. Valid actions: get_issue, search_issues, list_comments, create_comment, create_issue, update_issue, get_project, get_document, list_project_documents, search_projects, list_teams, list_users, list_workflow_states, create_document, update_project, update_document, graphql_query, graphql_mutation"
                )),
            });
        }

        if !self.is_action_allowed(action) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Action '{action}' is not enabled. Add it to linear.allowed_actions in config.toml. Currently allowed: {}",
                    self.allowed_actions.join(", ")
                )),
            });
        }

        let operation = match action {
            "get_issue"
            | "search_issues"
            | "list_comments"
            | "get_project"
            | "get_document"
            | "list_project_documents"
            | "search_projects"
            | "list_teams"
            | "list_users"
            | "list_workflow_states"
            | "graphql_query" => ToolOperation::Read,
            "create_comment" | "create_issue" | "update_issue" | "create_document"
            | "update_project" | "update_document" | "graphql_mutation" => ToolOperation::Act,
            _ => unreachable!(),
        };

        if let Err(error) = self
            .security
            .enforce_tool_operation(operation, &format!("linear.{action}"))
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        let result = match action {
            "get_issue" => self.get_issue(&args).await,
            "search_issues" => self.search_issues(&args).await,
            "list_comments" => self.list_comments(&args).await,
            "create_comment" => self.create_comment(&args).await,
            "create_issue" => self.create_issue(&args).await,
            "update_issue" => self.update_issue(&args).await,
            "get_project" => self.get_project(&args).await,
            "get_document" => self.get_document(&args).await,
            "list_project_documents" => self.list_project_documents(&args).await,
            "search_projects" => self.search_projects(&args).await,
            "list_teams" => self.list_teams(&args).await,
            "list_users" => self.list_users(&args).await,
            "list_workflow_states" => self.list_workflow_states(&args).await,
            "create_document" => self.create_document(&args).await,
            "update_project" => self.update_project(&args).await,
            "update_document" => self.update_document(&args).await,
            "graphql_query" => self.run_graphql_document(&args, false).await,
            "graphql_mutation" => self.run_graphql_document(&args, true).await,
            _ => unreachable!(),
        };

        match result {
            Ok(tool_result) => Ok(tool_result),
            Err(error) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error.to_string()),
            }),
        }
    }
}

fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn clamp_limit(limit: Option<u64>) -> u64 {
    limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE)
}

fn string_array(value: &Value, key: &str) -> Option<Vec<String>> {
    let values = value.get(key)?.as_array()?;
    let normalized = values
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    (!normalized.is_empty()).then_some(normalized)
}

fn build_issue_update_input(args: &Value) -> anyhow::Result<Value> {
    let mut input = Map::new();

    if let Some(title) = trimmed(args.get("title").and_then(Value::as_str)) {
        input.insert("title".into(), json!(title));
    }
    if let Some(description) = trimmed(args.get("description").and_then(Value::as_str)) {
        input.insert("description".into(), json!(description));
    }
    if let Some(state_id) = trimmed(args.get("state_id").and_then(Value::as_str)) {
        input.insert("stateId".into(), json!(state_id));
    }
    if let Some(assignee_id) = trimmed(args.get("assignee_id").and_then(Value::as_str)) {
        input.insert("assigneeId".into(), json!(assignee_id));
    }
    if let Some(priority) = args.get("priority").and_then(Value::as_i64) {
        input.insert("priority".into(), json!(priority));
    }
    if let Some(estimate) = args.get("estimate").and_then(Value::as_i64) {
        input.insert("estimate".into(), json!(estimate));
    }
    if let Some(due_date) = trimmed(args.get("due_date").and_then(Value::as_str)) {
        input.insert("dueDate".into(), json!(due_date));
    }
    if let Some(project_id) = trimmed(args.get("project_id").and_then(Value::as_str)) {
        input.insert("projectId".into(), json!(project_id));
    }
    if let Some(team_id) = trimmed(args.get("team_update_id").and_then(Value::as_str)) {
        input.insert("teamId".into(), json!(team_id));
    }
    if let Some(cycle_id) = trimmed(args.get("cycle_id").and_then(Value::as_str)) {
        input.insert("cycleId".into(), json!(cycle_id));
    }
    if let Some(parent_id) = trimmed(args.get("parent_id").and_then(Value::as_str)) {
        input.insert("parentId".into(), json!(parent_id));
    }
    if let Some(label_ids) = string_array(args, "label_ids") {
        input.insert("labelIds".into(), json!(label_ids));
    }
    if let Some(label_ids) = string_array(args, "added_label_ids") {
        input.insert("addedLabelIds".into(), json!(label_ids));
    }
    if let Some(label_ids) = string_array(args, "removed_label_ids") {
        input.insert("removedLabelIds".into(), json!(label_ids));
    }

    if input.is_empty() {
        anyhow::bail!(
            "update_issue requires at least one mutable field (for example title, description, state_id, assignee_id, priority, due_date, or labels)"
        );
    }

    Ok(Value::Object(input))
}

fn build_issue_create_input(args: &Value) -> anyhow::Result<Value> {
    let title = trimmed(args.get("title").and_then(Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("create_issue requires title"))?;
    let team_id = trimmed(args.get("team_id").and_then(Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("create_issue requires team_id"))?;

    let mut input = Map::new();
    input.insert("title".into(), json!(title));
    input.insert("teamId".into(), json!(team_id));

    if let Some(description) = trimmed(args.get("description").and_then(Value::as_str)) {
        input.insert("description".into(), json!(description));
    }
    if let Some(state_id) = trimmed(args.get("state_id").and_then(Value::as_str)) {
        input.insert("stateId".into(), json!(state_id));
    }
    if let Some(assignee_id) = trimmed(args.get("assignee_id").and_then(Value::as_str)) {
        input.insert("assigneeId".into(), json!(assignee_id));
    }
    if let Some(priority) = args.get("priority").and_then(Value::as_i64) {
        input.insert("priority".into(), json!(priority));
    }
    if let Some(estimate) = args.get("estimate").and_then(Value::as_i64) {
        input.insert("estimate".into(), json!(estimate));
    }
    if let Some(due_date) = trimmed(args.get("due_date").and_then(Value::as_str)) {
        input.insert("dueDate".into(), json!(due_date));
    }
    if let Some(project_id) = trimmed(args.get("project_id").and_then(Value::as_str)) {
        input.insert("projectId".into(), json!(project_id));
    }
    if let Some(cycle_id) = trimmed(args.get("cycle_id").and_then(Value::as_str)) {
        input.insert("cycleId".into(), json!(cycle_id));
    }
    if let Some(parent_id) = trimmed(args.get("parent_id").and_then(Value::as_str)) {
        input.insert("parentId".into(), json!(parent_id));
    }
    if let Some(label_ids) = string_array(args, "label_ids") {
        input.insert("labelIds".into(), json!(label_ids));
    }

    Ok(Value::Object(input))
}

fn build_project_update_input(args: &Value) -> anyhow::Result<Value> {
    let mut input = Map::new();

    if let Some(name) = trimmed(args.get("name").and_then(Value::as_str)) {
        input.insert("name".into(), json!(name));
    }
    if let Some(description) = trimmed(args.get("description").and_then(Value::as_str)) {
        input.insert("description".into(), json!(description));
    }
    if let Some(content) = trimmed(args.get("content").and_then(Value::as_str)) {
        input.insert("content".into(), json!(content));
    }
    if let Some(icon) = trimmed(args.get("icon").and_then(Value::as_str)) {
        input.insert("icon".into(), json!(icon));
    }
    if let Some(color) = trimmed(args.get("color").and_then(Value::as_str)) {
        input.insert("color".into(), json!(color));
    }
    if let Some(status_id) = trimmed(args.get("status_id").and_then(Value::as_str)) {
        input.insert("statusId".into(), json!(status_id));
    }
    if let Some(lead_id) = trimmed(args.get("lead_id").and_then(Value::as_str)) {
        input.insert("leadId".into(), json!(lead_id));
    }
    if let Some(start_date) = trimmed(args.get("start_date").and_then(Value::as_str)) {
        input.insert("startDate".into(), json!(start_date));
    }
    if let Some(target_date) = trimmed(args.get("target_date").and_then(Value::as_str)) {
        input.insert("targetDate".into(), json!(target_date));
    }
    if let Some(priority) = args.get("priority").and_then(Value::as_i64) {
        input.insert("priority".into(), json!(priority));
    }
    if let Some(team_ids) = string_array(args, "team_ids") {
        input.insert("teamIds".into(), json!(team_ids));
    }
    if let Some(member_ids) = string_array(args, "member_ids") {
        input.insert("memberIds".into(), json!(member_ids));
    }
    if let Some(label_ids) = string_array(args, "label_ids") {
        input.insert("labelIds".into(), json!(label_ids));
    }

    if input.is_empty() {
        anyhow::bail!(
            "update_project requires at least one mutable field (for example name, description, status_id, team_ids, member_ids, or target_date)"
        );
    }

    Ok(Value::Object(input))
}

fn build_document_create_input(args: &Value) -> anyhow::Result<Value> {
    let title = trimmed(args.get("title").and_then(Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("create_document requires title"))?;
    let project_id = trimmed(args.get("project_id").and_then(Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("create_document requires project_id"))?;

    let mut input = Map::new();
    input.insert("title".into(), json!(title));
    input.insert("projectId".into(), json!(project_id));

    if let Some(content) = trimmed(args.get("content").and_then(Value::as_str)) {
        input.insert("content".into(), json!(content));
    }
    if let Some(icon) = trimmed(args.get("icon").and_then(Value::as_str)) {
        input.insert("icon".into(), json!(icon));
    }
    if let Some(color) = trimmed(args.get("color").and_then(Value::as_str)) {
        input.insert("color".into(), json!(color));
    }
    if let Some(sort_order) = args.get("sort_order").and_then(Value::as_f64) {
        input.insert("sortOrder".into(), json!(sort_order));
    }

    Ok(Value::Object(input))
}

fn build_document_update_input(args: &Value) -> anyhow::Result<Value> {
    let mut input = Map::new();

    if let Some(title) = trimmed(args.get("title").and_then(Value::as_str)) {
        input.insert("title".into(), json!(title));
    }
    if let Some(content) = trimmed(args.get("content").and_then(Value::as_str)) {
        input.insert("content".into(), json!(content));
    }
    if let Some(icon) = trimmed(args.get("icon").and_then(Value::as_str)) {
        input.insert("icon".into(), json!(icon));
    }
    if let Some(color) = trimmed(args.get("color").and_then(Value::as_str)) {
        input.insert("color".into(), json!(color));
    }
    if let Some(project_id) = trimmed(args.get("project_id").and_then(Value::as_str)) {
        input.insert("projectId".into(), json!(project_id));
    }
    if let Some(sort_order) = args.get("sort_order").and_then(Value::as_f64) {
        input.insert("sortOrder".into(), json!(sort_order));
    }

    if input.is_empty() {
        anyhow::bail!(
            "update_document requires at least one mutable field (for example title, content, icon, color, project_id, or sort_order)"
        );
    }

    Ok(Value::Object(input))
}

fn json_tool_result<T: Serialize>(value: &T) -> anyhow::Result<ToolResult> {
    Ok(ToolResult {
        success: true,
        output: serde_json::to_string_pretty(value)?,
        error: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GraphQlDocumentKind {
    QueryLike,
    Mutation,
    Subscription,
    Unknown,
}

fn classify_graphql_document(document: &str) -> GraphQlDocumentKind {
    let trimmed = strip_graphql_prelude(document);

    if trimmed.starts_with('{') || starts_graphql_keyword(trimmed, "query") {
        GraphQlDocumentKind::QueryLike
    } else if starts_graphql_keyword(trimmed, "mutation") {
        GraphQlDocumentKind::Mutation
    } else if starts_graphql_keyword(trimmed, "subscription") {
        GraphQlDocumentKind::Subscription
    } else if starts_graphql_keyword(trimmed, "fragment") {
        GraphQlDocumentKind::QueryLike
    } else {
        GraphQlDocumentKind::Unknown
    }
}

fn strip_graphql_prelude(document: &str) -> &str {
    let mut rest = document.trim_start();
    loop {
        if let Some(comment) = rest.strip_prefix('#') {
            if let Some(newline_idx) = comment.find('\n') {
                rest = comment[newline_idx + 1..].trim_start();
                continue;
            }
            return "";
        }
        return rest;
    }
}

fn starts_graphql_keyword(document: &str, keyword: &str) -> bool {
    if !document.starts_with(keyword) {
        return false;
    }

    document[keyword.len()..]
        .chars()
        .next()
        .is_none_or(|ch| ch.is_whitespace() || matches!(ch, '{' | '('))
}

#[derive(Debug, Deserialize)]
struct GraphQlResponse<T> {
    data: Option<T>,
    #[serde(default)]
    errors: Option<Vec<GraphQlError>>,
}

#[derive(Debug, Deserialize)]
struct GraphQlError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct SearchIssuesData {
    #[serde(rename = "searchIssues")]
    search_issues: Connection<LinearIssueSummary>,
}

#[derive(Debug, Deserialize)]
struct GetIssueData {
    issue: Option<LinearIssue>,
}

#[derive(Debug, Deserialize)]
struct SearchProjectsData {
    #[serde(rename = "searchProjects")]
    search_projects: Connection<LinearProject>,
}

#[derive(Debug, Deserialize)]
struct GetDocumentData {
    document: Option<LinearDocument>,
}

#[derive(Debug, Deserialize)]
struct GetProjectData {
    project: Option<LinearProject>,
}

#[derive(Debug, Deserialize)]
struct ListProjectDocumentsData {
    project: Option<ProjectWithDocuments>,
}

#[derive(Debug, Deserialize)]
struct ListCommentsData {
    issue: Option<IssueWithComments>,
}

#[derive(Debug, Deserialize)]
struct ListTeamsData {
    teams: Connection<LinearTeam>,
}

#[derive(Debug, Deserialize)]
struct ListUsersData {
    users: Connection<LinearUser>,
}

#[derive(Debug, Deserialize)]
struct ListWorkflowStatesData {
    #[serde(rename = "workflowStates")]
    workflow_states: Connection<LinearState>,
}

#[derive(Debug, Deserialize)]
struct CommentCreateData {
    #[serde(rename = "commentCreate")]
    comment_create: CommentPayload,
}

#[derive(Debug, Deserialize)]
struct IssueCreateData {
    #[serde(rename = "issueCreate")]
    issue_create: IssuePayload,
}

#[derive(Debug, Deserialize)]
struct IssueUpdateData {
    #[serde(rename = "issueUpdate")]
    issue_update: IssuePayload,
}

#[derive(Debug, Deserialize)]
struct ProjectUpdateData {
    #[serde(rename = "projectUpdate")]
    project_update: ProjectPayload,
}

#[derive(Debug, Deserialize)]
struct DocumentCreateData {
    #[serde(rename = "documentCreate")]
    document_create: DocumentPayload,
}

#[derive(Debug, Deserialize)]
struct DocumentUpdateData {
    #[serde(rename = "documentUpdate")]
    document_update: DocumentPayload,
}

#[derive(Debug, Deserialize, Serialize)]
struct Connection<T> {
    #[serde(default)]
    nodes: Vec<T>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Deserialize, Serialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CommentPayload {
    success: bool,
    comment: LinearComment,
}

#[derive(Debug, Deserialize)]
struct IssuePayload {
    success: bool,
    issue: Option<LinearIssue>,
}

#[derive(Debug, Deserialize)]
struct ProjectPayload {
    success: bool,
    project: Option<LinearProject>,
}

#[derive(Debug, Deserialize)]
struct DocumentPayload {
    success: bool,
    document: Option<LinearDocument>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct LinearIssueSummary {
    id: String,
    identifier: String,
    title: String,
    priority: Option<i64>,
    url: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    team: LinearTeam,
    state: Option<LinearState>,
    assignee: Option<LinearUser>,
    project: Option<LinearProject>,
}

#[derive(Debug, Deserialize, Serialize)]
struct LinearIssue {
    id: String,
    identifier: String,
    title: String,
    description: Option<String>,
    priority: Option<i64>,
    estimate: Option<i64>,
    #[serde(rename = "dueDate")]
    due_date: Option<String>,
    url: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    team: LinearTeam,
    state: Option<LinearState>,
    assignee: Option<LinearUser>,
    project: Option<LinearProject>,
    labels: LabelsConnection,
}

#[derive(Debug, Deserialize, Serialize)]
struct IssueWithComments {
    id: String,
    identifier: String,
    title: String,
    comments: Connection<LinearComment>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct LinearComment {
    id: String,
    body: String,
    url: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    #[serde(rename = "parentId")]
    parent_id: Option<String>,
    #[serde(rename = "resolvedAt")]
    resolved_at: Option<String>,
    user: Option<LinearUser>,
    issue: Option<CommentIssueRef>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CommentIssueRef {
    id: String,
    identifier: String,
    title: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct LinearTeam {
    id: String,
    key: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct LinearState {
    id: String,
    name: String,
    color: Option<String>,
    description: Option<String>,
    position: Option<f64>,
    #[serde(rename = "type")]
    state_type: Option<String>,
    team: Option<LinearTeam>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct LinearProject {
    id: String,
    name: String,
    description: Option<String>,
    #[serde(rename = "slugId")]
    slug_id: Option<String>,
    icon: Option<String>,
    color: Option<String>,
    #[serde(rename = "startDate")]
    start_date: Option<String>,
    #[serde(rename = "targetDate")]
    target_date: Option<String>,
    priority: Option<i64>,
    url: Option<String>,
    lead: Option<LinearUser>,
    teams: Option<Connection<LinearTeam>>,
    members: Option<Connection<LinearUser>>,
    labels: Option<LabelsConnection>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct LinearDocument {
    id: String,
    title: String,
    summary: Option<String>,
    content: Option<String>,
    icon: Option<String>,
    color: Option<String>,
    #[serde(rename = "slugId")]
    slug_id: Option<String>,
    #[serde(rename = "sortOrder")]
    sort_order: Option<f64>,
    url: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
    #[serde(rename = "updatedAt")]
    updated_at: Option<String>,
    creator: Option<LinearUser>,
    #[serde(rename = "updatedBy")]
    updated_by: Option<LinearUser>,
    project: Option<LinearProject>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProjectWithDocuments {
    id: String,
    name: String,
    documents: Connection<LinearDocument>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct LinearUser {
    id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    email: Option<String>,
    active: Option<bool>,
    url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct LabelsConnection {
    #[serde(default)]
    nodes: Vec<LinearLabel>,
}

#[derive(Debug, Deserialize, Serialize)]
struct LinearLabel {
    id: String,
    name: String,
    color: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_issue_update_input_requires_changes() {
        let error = build_issue_update_input(&json!({})).unwrap_err();
        assert!(error.to_string().contains("at least one mutable field"));
    }

    #[test]
    fn build_issue_update_input_maps_fields() {
        let input = build_issue_update_input(&json!({
            "title": "Tighten webhook parsing",
            "priority": 2,
            "state_id": "state-123",
            "label_ids": ["label-a", "label-b"]
        }))
        .unwrap();

        assert_eq!(input["title"], "Tighten webhook parsing");
        assert_eq!(input["priority"], 2);
        assert_eq!(input["stateId"], "state-123");
        assert_eq!(input["labelIds"], json!(["label-a", "label-b"]));
    }

    #[test]
    fn build_issue_create_input_requires_title_and_team() {
        let error = build_issue_create_input(&json!({"title": "Missing team"})).unwrap_err();
        assert!(error.to_string().contains("team_id"));
    }

    #[test]
    fn build_issue_create_input_maps_fields() {
        let input = build_issue_create_input(&json!({
            "title": "Hook up Linear webhooks",
            "team_id": "team-1",
            "state_id": "state-1",
            "project_id": "project-1",
            "label_ids": ["label-1", "label-2"]
        }))
        .unwrap();

        assert_eq!(input["title"], "Hook up Linear webhooks");
        assert_eq!(input["teamId"], "team-1");
        assert_eq!(input["stateId"], "state-1");
        assert_eq!(input["projectId"], "project-1");
        assert_eq!(input["labelIds"], json!(["label-1", "label-2"]));
    }

    #[test]
    fn build_project_update_input_maps_fields() {
        let input = build_project_update_input(&json!({
            "name": "Linear rollout",
            "status_id": "status-1",
            "team_ids": ["team-a"],
            "member_ids": ["user-a", "user-b"]
        }))
        .unwrap();

        assert_eq!(input["name"], "Linear rollout");
        assert_eq!(input["statusId"], "status-1");
        assert_eq!(input["teamIds"], json!(["team-a"]));
        assert_eq!(input["memberIds"], json!(["user-a", "user-b"]));
    }

    #[test]
    fn build_document_create_input_requires_title_and_project() {
        let error = build_document_create_input(&json!({"title": "Missing project"})).unwrap_err();
        assert!(error.to_string().contains("project_id"));
    }

    #[test]
    fn build_document_create_input_maps_fields() {
        let input = build_document_create_input(&json!({
            "title": "Runbook",
            "project_id": "project-1",
            "content": "# Hello",
            "icon": ":book:",
            "color": "#112233",
            "sort_order": 12.5
        }))
        .unwrap();

        assert_eq!(input["title"], "Runbook");
        assert_eq!(input["projectId"], "project-1");
        assert_eq!(input["content"], "# Hello");
        assert_eq!(input["icon"], ":book:");
        assert_eq!(input["color"], "#112233");
        assert_eq!(input["sortOrder"], 12.5);
    }

    #[test]
    fn build_document_update_input_requires_changes() {
        let error = build_document_update_input(&json!({})).unwrap_err();
        assert!(error.to_string().contains("at least one mutable field"));
    }

    #[test]
    fn build_document_update_input_maps_fields() {
        let input = build_document_update_input(&json!({
            "title": "Updated runbook",
            "project_id": "project-2",
            "sort_order": 4.0
        }))
        .unwrap();

        assert_eq!(input["title"], "Updated runbook");
        assert_eq!(input["projectId"], "project-2");
        assert_eq!(input["sortOrder"], 4.0);
    }

    #[test]
    fn parameters_schema_lists_supported_actions() {
        let tool = LinearTool::new(
            "https://api.linear.app/graphql".into(),
            "test-key".into(),
            vec!["get_issue".into()],
            Arc::new(SecurityPolicy::default()),
            30,
        );

        let schema = tool.parameters_schema();
        let actions = schema["properties"]["action"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();

        assert!(actions.contains(&"get_issue"));
        assert!(actions.contains(&"search_issues"));
        assert!(actions.contains(&"list_comments"));
        assert!(actions.contains(&"create_comment"));
        assert!(actions.contains(&"create_issue"));
        assert!(actions.contains(&"update_issue"));
        assert!(actions.contains(&"get_project"));
        assert!(actions.contains(&"get_document"));
        assert!(actions.contains(&"list_project_documents"));
        assert!(actions.contains(&"search_projects"));
        assert!(actions.contains(&"list_teams"));
        assert!(actions.contains(&"list_users"));
        assert!(actions.contains(&"list_workflow_states"));
        assert!(actions.contains(&"create_document"));
        assert!(actions.contains(&"update_project"));
        assert!(actions.contains(&"update_document"));
        assert!(actions.contains(&"graphql_query"));
        assert!(actions.contains(&"graphql_mutation"));
    }

    #[test]
    fn classify_graphql_document_detects_operation_kind() {
        assert_eq!(
            classify_graphql_document("{ viewer { id } }"),
            GraphQlDocumentKind::QueryLike
        );
        assert_eq!(
            classify_graphql_document("query Viewer { viewer { id } }"),
            GraphQlDocumentKind::QueryLike
        );
        assert_eq!(
            classify_graphql_document(
                "mutation UpdateIssue { issueUpdate(id: \"1\", input: {}) { success } }"
            ),
            GraphQlDocumentKind::Mutation
        );
        assert_eq!(
            classify_graphql_document(
                "# comment\nmutation UpdateIssue { issueUpdate(id: \"1\", input: {}) { success } }"
            ),
            GraphQlDocumentKind::Mutation
        );
        assert_eq!(
            classify_graphql_document("subscription Events { notifications { id } }"),
            GraphQlDocumentKind::Subscription
        );
    }
}
