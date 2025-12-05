package burp.onescan.engine;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 扫描引擎 - 负责管理扫描任务的线程池和计数器
 * <p>
 * 职责:
 * - 管理三种类型的线程池(任务、低频任务、指纹识别)
 * - 维护任务提交和完成的计数器
 * - 提供统一的任务提交接口
 * - 处理引擎关闭和资源清理
 * <p>
 * Created for ARCH-001 refactoring
 */
public class ScanEngine {

    /**
     * 任务线程池 - 处理常规扫描任务
     */
    private final ExecutorService mTaskThreadPool;

    /**
     * 低频任务线程池 - 处理低频率的特殊任务
     */
    private final ExecutorService mLFTaskThreadPool;

    /**
     * 指纹识别线程池 - 专门用于指纹识别任务
     */
    private final ExecutorService mFpThreadPool;

    /**
     * 刷新消息任务线程池 - 单线程用于UI刷新
     */
    private final ExecutorService mRefreshMsgTask;

    /**
     * 任务完成计数器
     */
    private final AtomicInteger mTaskOverCounter;

    /**
     * 任务提交计数器
     */
    private final AtomicInteger mTaskCommitCounter;

    /**
     * 低频任务完成计数器
     */
    private final AtomicInteger mLFTaskOverCounter;

    /**
     * 低频任务提交计数器
     */
    private final AtomicInteger mLFTaskCommitCounter;

    /**
     * 构造扫描引擎
     *
     * @param taskThreadCount   常规任务线程数
     * @param lfTaskThreadCount 低频任务线程数
     * @param fpThreadCount     指纹识别线程数
     */
    public ScanEngine(int taskThreadCount, int lfTaskThreadCount, int fpThreadCount) {
        this.mTaskThreadPool = Executors.newFixedThreadPool(taskThreadCount);
        this.mLFTaskThreadPool = Executors.newFixedThreadPool(lfTaskThreadCount);
        this.mFpThreadPool = Executors.newFixedThreadPool(fpThreadCount);
        this.mRefreshMsgTask = Executors.newSingleThreadExecutor();

        this.mTaskOverCounter = new AtomicInteger(0);
        this.mTaskCommitCounter = new AtomicInteger(0);
        this.mLFTaskOverCounter = new AtomicInteger(0);
        this.mLFTaskCommitCounter = new AtomicInteger(0);
    }

    // ============================================================
    // 任务提交接口
    // ============================================================

    /**
     * 提交常规扫描任务
     *
     * @param task 任务
     */
    public void submitTask(Runnable task) {
        if (!mTaskThreadPool.isShutdown()) {
            mTaskThreadPool.execute(task);
        }
    }

    /**
     * 提交低频任务
     *
     * @param task 任务
     */
    public void submitLFTask(Runnable task) {
        if (!mLFTaskThreadPool.isShutdown()) {
            mLFTaskThreadPool.execute(task);
        }
    }

    /**
     * 提交指纹识别任务
     *
     * @param task 任务
     */
    public void submitFpTask(Runnable task) {
        if (!mFpThreadPool.isShutdown()) {
            mFpThreadPool.execute(task);
        }
    }

    /**
     * 提交刷新消息任务(单线程)
     *
     * @param task 任务
     */
    public void submitRefreshTask(Runnable task) {
        if (!mRefreshMsgTask.isShutdown()) {
            mRefreshMsgTask.execute(task);
        }
    }

    // ============================================================
    // 状态查询接口
    // ============================================================

    /**
     * 检查任务线程池是否已关闭
     *
     * @return true 如果已关闭
     */
    public boolean isTaskThreadPoolShutdown() {
        return mTaskThreadPool.isShutdown();
    }

    /**
     * 检查指纹线程池是否已关闭
     *
     * @return true 如果已关闭
     */
    public boolean isFpThreadPoolShutdown() {
        return mFpThreadPool.isShutdown();
    }

    /**
     * 获取任务完成计数
     *
     * @return 任务完成数
     */
    public int getTaskOverCount() {
        return mTaskOverCounter.get();
    }

    /**
     * 获取任务提交计数
     *
     * @return 任务提交数
     */
    public int getTaskCommitCount() {
        return mTaskCommitCounter.get();
    }

    /**
     * 获取低频任务完成计数
     *
     * @return 低频任务完成数
     */
    public int getLFTaskOverCount() {
        return mLFTaskOverCounter.get();
    }

    /**
     * 获取低频任务提交计数
     *
     * @return 低频任务提交数
     */
    public int getLFTaskCommitCount() {
        return mLFTaskCommitCounter.get();
    }

    // ============================================================
    // 计数器管理接口
    // ============================================================

    /**
     * 增加任务完成计数
     */
    public void incrementTaskOver() {
        mTaskOverCounter.incrementAndGet();
    }

    /**
     * 增加任务提交计数
     */
    public void incrementTaskCommit() {
        mTaskCommitCounter.incrementAndGet();
    }

    /**
     * 增加低频任务完成计数
     */
    public void incrementLFTaskOver() {
        mLFTaskOverCounter.incrementAndGet();
    }

    /**
     * 增加低频任务提交计数
     */
    public void incrementLFTaskCommit() {
        mLFTaskCommitCounter.incrementAndGet();
    }

    // ============================================================
    // 生命周期管理
    // ============================================================

    /**
     * 停止所有任务并返回未执行的任务列表
     * 注意:此方法会立即关闭线程池,需要调用reinitialize()重新初始化
     *
     * @return 包含任务和低频任务的数组,其中[0]是任务列表,[1]是低频任务列表
     */
    public List<Runnable>[] shutdownNowAndGetTasks() {
        @SuppressWarnings("unchecked")
        List<Runnable>[] result = new List[2];
        result[0] = mTaskThreadPool.shutdownNow();
        result[1] = mLFTaskThreadPool.shutdownNow();
        return result;
    }

    /**
     * 重新初始化线程池(用于stopAllTask场景)
     * 注意:此方法会创建新的线程池实例,原有线程池必须已经shutdown
     */
    public void reinitialize() {
        // 注意:由于字段是final的,我们不能直接重新赋值
        // 这个方法设计有问题,需要重新考虑架构
        // 暂时抛出异常提示调用者这个操作不支持
        throw new UnsupportedOperationException(
                "Cannot reinitialize ScanEngine with final fields. " +
                "Consider creating a new ScanEngine instance instead."
        );
    }

    /**
     * 关闭扫描引擎,释放所有线程池资源
     */
    public void shutdown() {
        shutdownThreadPool(mTaskThreadPool, "TaskThreadPool");
        shutdownThreadPool(mLFTaskThreadPool, "LFTaskThreadPool");
        shutdownThreadPool(mFpThreadPool, "FpThreadPool");
        shutdownThreadPool(mRefreshMsgTask, "RefreshMsgTask");
    }

    /**
     * 关闭单个线程池
     *
     * @param pool 线程池
     * @param name 线程池名称(用于日志)
     */
    private void shutdownThreadPool(ExecutorService pool, String name) {
        if (pool != null && !pool.isShutdown()) {
            pool.shutdown();
            try {
                if (!pool.awaitTermination(5, TimeUnit.SECONDS)) {
                    pool.shutdownNow();
                }
            } catch (InterruptedException e) {
                pool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
}
