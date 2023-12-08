import { For, Show, createSignal, onMount } from "solid-js";
import "./App.css";
import { JSX } from "solid-js";

function App() {
  const [filePath, setFilePath] = createSignal(
    "../ast_analyzer/java_ast_local_file_analysis.json"
  );
  const [output, setOutput] = createSignal("");
  const [fileContent, setFileContent] = createSignal("");
  const [jsonData, setJsonData] = createSignal<any>({});
  const [status, setStatus] = createSignal("init");
  const [fileType, setFileType] = createSignal(0);

  const fetchRelatedData = async (path: string) => {
    console.log(path);
    try {
      // const data = await import(`${path}`);
      // setOutput(JSON.stringify(data, null, 2));
      console.log("fetching data", path);
    } catch (error) {
      console.error("Error importing the module:", error);
      setOutput("Error importing the module");
    }
  };

  const dropdownSelect = (event: Event) => {
    const value = (event.target as HTMLSelectElement).value;
    console.log("dropdown selected");
    const thirdPartyDefaultPath =
      "../../../ast_analyzer/java_ast_third_party_analysis.json";
    const localDefaultPath =
      "../../../ast_analyzer/java_ast_local_file_analysis.json";

    if (value === "1") {
      setFilePath(localDefaultPath);
      fetchRelatedData(localDefaultPath);
      setFileType(1);
    } else if (value === "2") {
      setFilePath(thirdPartyDefaultPath);
      fetchRelatedData(thirdPartyDefaultPath);
      setFileType(2);
    } else {
      setFilePath("None");
    }
  };

  onMount(() => {
    fetchRelatedData(filePath());
  });

  const handleFileChange = (event: Event) => {
    setStatus("loading");
    setFilePath((event.target as HTMLInputElement).value);
    const file = (event.target as HTMLInputElement).files?.[0];
    if (!file) {
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      if (!e.target) return;
      const result = e.target.result;
      if (typeof result === "string") {
        setFileContent(result);

        try {
          const parsedData = JSON.parse(result);
          setJsonData(parsedData);
          console.log("parsed data", jsonData());
          setStatus("loaded");
        } catch (error) {
          console.error("Error parsing JSON:", error);
          setJsonData({});
        }
      }
    };

    reader.readAsText(file);
  };

  return (
    <div class="w-100 h-100 p-5">
      <h1 class="fs-1 text-center">AST Visualizer</h1>
      <div class="d-flex justify-content-center">
        <div>
          <div class="form-floating">
            <select
              class="form-select"
              style={{ width: "300px" }}
              id="floatingSelect"
              aria-label="Floating label select example"
              onChange={dropdownSelect}
            >
              <option value="0" selected>
                None
              </option>
              <option value="1">Local Ast Files</option>
              <option value="2">Third Party Ast Files</option>
            </select>
            <label for="floatingSelect" class="text-success">
              Choose an AST category
            </label>
          </div>
          <div class="text-start mt-3">
            <small class="text-primary fw-bolder ">Upload your own file</small>
            <div class="input-group input-group-default">
              <input
                type="file"
                class="form-control"
                aria-label="Sizing example input"
                aria-describedby="inputGroup-sizing-lg"
                onChange={handleFileChange}
              />
            </div>
          </div>
        </div>

        <div class="ps-3">
          <div class="card ps-2" style="width: auto">
            <div class="p-1">
              <p>Default file path:</p>
              <code>{filePath()}</code>
            </div>
          </div>
        </div>
      </div>
      <hr
        class="rounded"
        style="border-top: 8px solid #bbb; border-radius: 5px"
      />
      <div>
        <h3>File Content:</h3>
        <div>
          <Show when={status() == "init"}>
            <p>Waiting for file upload</p>
          </Show>
          <Show when={status() == "loading"}>
            <p>Loading...</p>
          </Show>
          <Show when={status() == "error"}>
            <p>Error loading file</p>
          </Show>

          <Show when={status() == "loaded"}>
            <Show when={fileType() == 1}>
              <div>
                <code> Path: {filePath()}</code>
                <div class="d-flex align-items-top align-self-top flex-wrap">
                  <For
                    each={Object.values(jsonData() as any[])[0] ?? ["none"]}
                    fallback={<div>Loading...</div>}
                  >
                    {(item) => (
                      <div class="flex">
                        <div class="card text-start p-2 m-2 ">
                          <div
                            class={`badge ${
                              item.thirdPartyInfo != null
                                ? "bg-primary"
                                : "bg-secondary"
                            } w-20`}
                          >
                            {item.thirdPartyInfo != null
                              ? "Local function"
                              : "External function"}
                          </div>
                          <p class="fw-bold fs-3">{item.methodName}</p>
                          <p> Line: {item.line}</p>
                          <p> Called as: {item.methodCallLine}</p>

                          {item.thirdPartyInfo != null ? (
                            <div class="alert alert-info" role="alert">
                              <div>
                                className:
                                <p class="fw-bold">
                                  {item.thirdPartyInfo.self.className}
                                </p>
                              </div>
                              <p>
                                External Functions include:
                                {item.thirdPartyInfo.functions.length}
                              </p>
                              <p> line: {item.thirdPartyInfo.self.line}</p>
                            </div>
                          ) : null}
                        </div>
                      </div>
                    )}
                  </For>
                </div>
              </div>
            </Show>
          </Show>
        </div>
      </div>
    </div>
  );
}

export default App;
