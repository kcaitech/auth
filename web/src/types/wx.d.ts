/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

declare namespace wx {
    interface LoginResult {
        code: string;
        errMsg: string;
    }

    function login(): Promise<LoginResult>;
} 