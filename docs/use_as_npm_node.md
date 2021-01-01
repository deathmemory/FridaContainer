# 作为 npm node 模块使用

## 配置参考

### package.json

```json
{
// ......
  "devDependencies": {
    "@dmemory/fridacontainer": "latest"
  }
}
```

### tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ESNEXT",
    "module": "ESNEXT",
    "allowJs": true,
    "strict": true,
    "moduleResolution": "node",
    "baseUrl": "./",
    "paths": {
      "fridacontainer/*": [
        "./node_modules/@dmemory/fridacontainer/dist/*"
      ]
    },
    "skipLibCheck": true,
    "allowSyntheticDefaultImports": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true
  }
}
```

## 安装 node
```bash
sudo npm install
```

## 引用

因为在 `tsconfig.json` 中 `baseUrl` 和 `paths` 重定向了搜索路径为 `fridacontainer`，所以下面可以缩短导入路径长度。

```typescript
import {FCAnd} from "fridacontainer/FCAnd"

function main() {
    FCAnd.hook_url(true);
}
```
