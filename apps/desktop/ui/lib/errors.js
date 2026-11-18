// What a failed call says, in words a person can act on. The engine's own code and message are always
// kept and shown; the hint only adds what to do about it.
const BUDGET = 'SQL_WORK_BUDGET';

export function describeError(error) {
  const e = error ?? {};
  const code = String(e.code ?? 'UNKNOWN');
  const message = String(e.message ?? '');
  let hint = '';
  switch (code) {
    case 'QUOTA_EXCEEDED':
      hint = message === BUDGET
        ? '查询超出了 SQL 工作量预算（执行步数或扫描行数）。到“引擎”页调高预算，或加上更具体的过滤条件。结果没有被截断后当作完整结果返回。'
        : '超出了引擎的资源配额。结果没有被截断后当作完整结果返回。';
      break;
    case 'DEADLINE_EXCEEDED':
      hint = '超过了期限。引擎已结束这次请求（并关闭了该输入集）；下一次操作会自动重新打开输入。';
      break;
    case 'CANCELLED':
      hint = '已取消。引擎进程已结束，已打开的输入会在下一次操作时自动重新打开。';
      break;
    case 'ENGINE_BUSY':
      hint = '引擎一次只处理一个请求。等当前请求结束，或点底部的“取消”。';
      break;
    case 'ENGINE_NOT_FOUND':
      hint = '找不到引擎程序。设置环境变量 MDD_ENGINE，或把 meguvizdexdash 放在工作台程序旁边。';
      break;
    case 'ENGINE_LOST':
      hint = '引擎进程意外结束。最近的标准错误输出在详情里；输入会在下一次操作时重新打开。';
      break;
    case 'INVALID_INPUT':
    case 'PARTIAL_INPUT':
      hint = '输入不是受支持的 DEX/APK/ZIP，或已损坏。引擎没有把它当作空输入接受。';
      break;
    case 'INPUT_NOT_FOUND':
      hint = '路径不存在，或不是一个文件。';
      break;
    case 'UNSUPPORTED_QUERY':
    case 'UNSUPPORTED_CAPABILITY':
      hint = '引擎暂不支持这条语句或这项能力；这是明确的拒绝，不是空结果。';
      break;
    case 'INVALID_ARGUMENT':
      hint = '参数或 SQL 无效。';
      break;
    case 'UNKNOWN_HANDLE':
      hint = '这个输入集已经关闭。请在“输入”页重新打开。';
      break;
    case 'EXPORT_TRUNCATED':
    case 'EXPORT_SHORT':
    case 'EXPORT_COUNT':
      hint = '导出没有完成，文件已删除，不会留下残缺文件。';
      break;
    default:
      break;
  }
  return { code, message, hint, details: e };
}

export function isCancelled(error) {
  return error?.code === 'CANCELLED';
}
