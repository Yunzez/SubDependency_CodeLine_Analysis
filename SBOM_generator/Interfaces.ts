export interface CustomData {
    [filePath: string]: MethodCallInfo[];
}

export interface MethodCallInfo {
    methodName: string;
    methodCallLine: string;
    line: string;
    thirdPartyInfo?: ThirdPartyInfo;
}

export interface ThirdPartyInfo {
    functions: any[];
    self: SelfInfo;
}

export interface FunctionInfo {
    // Define properties for FunctionInfo if needed
    // For example:
    // functionName: string;
}

export interface SelfInfo {
    line: string;
    file: string;
    className: string;
}