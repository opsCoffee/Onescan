package burp.common.helper;

/**
 * QPS 限制器
 * <p>
 * 使用滑动窗口算法实现QPS限流,关键优化:将计算与sleep分离,避免持有锁期间阻塞
 * <p>
 * @author kenyon
 * @mail kenyon <kenyon@noreply.localhost>
 * <p>
 * Created by vaycore on 2023-02-23.
 * Refactored by kenyon on 2025-12-04.
 */
public class QpsLimiter {

    /**
     * 以每秒的间隔计算
     */
    private static final long PERIOD_MS = 1000;

    /**
     * 接收请求时间数组 (滑动窗口)
     */
    private final long[] mAccessTime;

    /**
     * 限制数量,最低为1
     */
    private final int mLimit;

    /**
     * 限制延时 (0 表示不延时)
     */
    private final int mDelayMs;

    /**
     * 指向最早请求时间的位置
     */
    private int mPosition;

    public QpsLimiter(int limit) {
        this(limit, 0);
    }

    public QpsLimiter(int limit, int delayMs) {
        if (limit <= 0) {
            throw new IllegalArgumentException("Illegal limit value: " + limit);
        }
        this.mLimit = limit;
        this.mDelayMs = Math.max(0, delayMs);
        this.mPosition = 0;
        this.mAccessTime = new long[limit];
    }

    /**
     * 对执行点进行限制
     * <p>
     * 优化点:
     * 1. 将 sleep 移到 synchronized 块外部,避免持有锁期间阻塞
     * 2. synchronized 块只保护共享状态的修改,时间极短
     * 3. 关键:先计算需要等待的时间,释放锁后再 sleep
     */
    public void limit() throws InterruptedException {
        // 如果线程中断,立即退出
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("Thread interrupted, can't limit it");
        }

        // 优先使用固定延时模式 (简单但低效)
        if (mDelayMs > 0) {
            Thread.sleep(mDelayMs);
            return;
        }

        // 滑动窗口限流算法:关键是分离计算和等待
        long sleepMs = calculateSleepTime();

        // 重要:在 synchronized 块外部 sleep,不阻塞其他线程
        if (sleepMs > 0) {
            Thread.sleep(sleepMs);
        }
    }

    /**
     * 计算需要 sleep 的时间并更新时间戳
     * <p>
     * synchronized 块只保护共享状态(mAccessTime, mPosition),操作极快
     */
    private synchronized long calculateSleepTime() {
        long curTime = System.currentTimeMillis();
        long oldestTime = mAccessTime[mPosition];

        long sleepMs = 0;
        if (curTime - oldestTime < PERIOD_MS) {
            // 未达到时间间隔,计算需要等待的时间
            sleepMs = PERIOD_MS - (curTime - oldestTime) + 1;
            curTime += sleepMs;  // 预测 sleep 后的时间
        }

        // 更新时间戳和位置指针
        mAccessTime[mPosition] = curTime;
        mPosition = (mPosition + 1) % mLimit;

        return sleepMs;
    }

    /**
     * 尝试获取限流许可 (非阻塞)
     *
     * @param timeoutMs 超时时间 (毫秒)
     * @return true 成功获取, false 超时
     */
    public boolean tryLimit(long timeoutMs) throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("Thread interrupted");
        }

        if (mDelayMs > 0) {
            if (mDelayMs > timeoutMs) {
                return false;
            }
            Thread.sleep(mDelayMs);
            return true;
        }

        long sleepMs = calculateSleepTime();
        if (sleepMs > timeoutMs) {
            return false;  // 需要等待时间超过超时限制
        }

        if (sleepMs > 0) {
            Thread.sleep(sleepMs);
        }
        return true;
    }
}
