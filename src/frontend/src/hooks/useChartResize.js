import { useEffect } from 'react';

export default function useChartResize(echartsRef, containerRef, delay = 300) {
    useEffect(() => {
        let timeoutId;
        const observer = new ResizeObserver((entries) => {
            clearTimeout(timeoutId);
            timeoutId = setTimeout(() => {
                if (!echartsRef.current || !containerRef.current) return;

                for (let entry of entries) {
                    const { width, height } = entry.contentRect;
                    if (width > 0 && height > 0) {
                        const instance = echartsRef.current.getEchartsInstance();
                        if (instance) {
                            instance.resize();
                        }
                    }
                }
            }, delay);
        });

        if (containerRef.current) {
            observer.observe(containerRef.current);
        }

        return () => {
            clearTimeout(timeoutId);
            observer.disconnect();
        };
    }, [echartsRef, containerRef, delay]);
}
