import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

def generate_comparison_chart():
    # Data from our experiment
    models = ['Logistic\nRegression', 'KNN', 'Random\nForest', 'Decision\nTree', 'Gradient\nBoosting', 'Naive\nBayes']
    accuracy = [0.9980, 0.9975, 0.9973, 0.9969, 0.9961, 0.8556]
    f1_score = [0.9971, 0.9963, 0.9960, 0.9954, 0.9942, 0.7361]

    # Set up the matplotlib figure
    sns.set_theme(style="whitegrid")
    fig, ax = plt.subplots(figsize=(12, 7))

    # Bar width and positions
    x = np.arange(len(models))
    width = 0.35

    # Create bars
    rects1 = ax.bar(x - width/2, accuracy, width, label='Accuracy', color='#4C72B0')
    rects2 = ax.bar(x + width/2, f1_score, width, label='F1-Score', color='#55A868')

    # Add text and labels
    ax.set_ylabel('Метрики', fontsize=14, fontweight='bold')
    ax.set_title('Научное сравнение ML моделей для обнаружения на основе URL (Модель B)', fontsize=16, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=12)
    ax.legend(loc='lower right', fontsize=12)
    ax.set_ylim(0.7, 1.05) # Zoom in to see the differences clearly

    # Add numbers on top of bars
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.4f}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=10)

    autolabel(rects1)
    autolabel(rects2)

    plt.tight_layout()
    
    # Save the chart to the docs folder
    output_path = os.path.join(os.path.dirname(__file__), "..", "docs", "model_b_comparison_ru.png")
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Chart successfully saved to: {output_path}")

if __name__ == "__main__":
    generate_comparison_chart()
