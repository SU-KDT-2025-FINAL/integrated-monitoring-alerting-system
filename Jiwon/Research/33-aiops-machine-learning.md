# AIOps 및 머신러닝 (Phase 3-3)

## 개요
인공지능과 머신러닝을 활용한 지능형 모니터링 시스템 구축, 이상 감지, 예측 분석, 근본 원인 분석 자동화 방법을 학습합니다.

## 1. 이상 감지 (Anomaly Detection)

### 1.1 통계적 이상 감지 알고리즘

**Z-Score 기반 이상 감지**
```python
# statistical_anomaly_detection.py
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt

class StatisticalAnomalyDetector:
    def __init__(self, window_size=100, z_threshold=3.0):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self.scaler = StandardScaler()
        
    def detect_zscore_anomalies(self, data, column):
        """Z-Score 기반 이상 감지"""
        rolling_mean = data[column].rolling(window=self.window_size).mean()
        rolling_std = data[column].rolling(window=self.window_size).std()
        
        z_scores = np.abs((data[column] - rolling_mean) / rolling_std)
        anomalies = z_scores > self.z_threshold
        
        return anomalies, z_scores
    
    def detect_iqr_anomalies(self, data, column):
        """IQR 기반 이상 감지"""
        Q1 = data[column].quantile(0.25)
        Q3 = data[column].quantile(0.75)
        IQR = Q3 - Q1
        
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR
        
        anomalies = (data[column] < lower_bound) | (data[column] > upper_bound)
        return anomalies
    
    def detect_seasonal_anomalies(self, data, column, period=24):
        """계절성을 고려한 이상 감지"""
        # 계절성 분해
        from statsmodels.tsa.seasonal import seasonal_decompose
        
        decomposition = seasonal_decompose(
            data[column].dropna(), 
            model='additive', 
            period=period
        )
        
        residuals = decomposition.resid.dropna()
        
        # 잔차에 대한 Z-Score 계산
        z_scores = np.abs(stats.zscore(residuals))
        anomalies = z_scores > self.z_threshold
        
        return anomalies, residuals, decomposition

# 실시간 이상 감지 시스템
class RealTimeAnomalyDetector:
    def __init__(self, prometheus_client):
        self.prometheus = prometheus_client
        self.models = {}
        self.alert_thresholds = {}
        
    def initialize_models(self, metrics_config):
        """메트릭별 이상 감지 모델 초기화"""
        for metric_name, config in metrics_config.items():
            if config['method'] == 'isolation_forest':
                from sklearn.ensemble import IsolationForest
                model = IsolationForest(
                    contamination=config.get('contamination', 0.1),
                    random_state=42
                )
            elif config['method'] == 'local_outlier_factor':
                from sklearn.neighbors import LocalOutlierFactor
                model = LocalOutlierFactor(
                    n_neighbors=config.get('n_neighbors', 20),
                    contamination=config.get('contamination', 0.1)
                )
            elif config['method'] == 'one_class_svm':
                from sklearn.svm import OneClassSVM
                model = OneClassSVM(
                    nu=config.get('nu', 0.1),
                    kernel=config.get('kernel', 'rbf')
                )
            
            self.models[metric_name] = {
                'model': model,
                'config': config,
                'trained': False
            }
    
    def train_models(self, training_period_hours=168):  # 1주일
        """과거 데이터로 모델 훈련"""
        end_time = time.time()
        start_time = end_time - (training_period_hours * 3600)
        
        for metric_name, model_info in self.models.items():
            try:
                # 훈련 데이터 수집
                query = model_info['config']['query']
                training_data = self.prometheus.query_range(
                    query=query,
                    start=start_time,
                    end=end_time,
                    step=model_info['config'].get('step', '1m')
                )
                
                # 데이터 전처리
                processed_data = self._preprocess_training_data(training_data)
                
                if len(processed_data) > 100:  # 최소 데이터 요구사항
                    # 모델 훈련
                    if model_info['config']['method'] == 'local_outlier_factor':
                        # LOF는 fit_predict 사용
                        predictions = model_info['model'].fit_predict(processed_data)
                    else:
                        model_info['model'].fit(processed_data)
                    
                    model_info['trained'] = True
                    print(f"모델 훈련 완료: {metric_name}")
                else:
                    print(f"훈련 데이터 부족: {metric_name}")
                    
            except Exception as e:
                print(f"모델 훈련 실패 {metric_name}: {e}")
    
    def detect_anomalies(self, metric_name, recent_data):
        """실시간 이상 감지"""
        if metric_name not in self.models:
            return None
            
        model_info = self.models[metric_name]
        if not model_info['trained']:
            return None
            
        try:
            # 데이터 전처리
            processed_data = self._preprocess_realtime_data(recent_data)
            
            # 이상 감지 수행
            if model_info['config']['method'] == 'local_outlier_factor':
                # LOF는 새로운 데이터에 대해 다시 훈련 필요
                combined_data = np.vstack([
                    model_info.get('training_data', processed_data),
                    processed_data
                ])
                predictions = model_info['model'].fit_predict(combined_data)
                anomaly_scores = model_info['model'].negative_outlier_factor_
                return predictions[-len(processed_data):], anomaly_scores[-len(processed_data):]
            else:
                predictions = model_info['model'].predict(processed_data)
                if hasattr(model_info['model'], 'decision_function'):
                    anomaly_scores = model_info['model'].decision_function(processed_data)
                else:
                    anomaly_scores = None
                    
                return predictions, anomaly_scores
                
        except Exception as e:
            print(f"이상 감지 실패 {metric_name}: {e}")
            return None
    
    def _preprocess_training_data(self, prometheus_data):
        """Prometheus 데이터 전처리"""
        # 시계열 데이터를 특성 벡터로 변환
        features = []
        
        for result in prometheus_data['data']['result']:
            values = result['values']
            
            # 시간별 값들을 특성으로 변환
            value_series = [float(v[1]) for v in values if v[1] != 'NaN']
            
            if len(value_series) > 0:
                # 통계적 특성 추출
                feature_vector = [
                    np.mean(value_series),
                    np.std(value_series),
                    np.min(value_series),
                    np.max(value_series),
                    np.percentile(value_series, 25),
                    np.percentile(value_series, 75),
                    len(value_series)
                ]
                features.append(feature_vector)
        
        return np.array(features)
```

### 1.2 시계열 예측을 위한 Prophet/ARIMA

**Prophet 기반 예측 시스템**
```python
# time_series_forecasting.py
from prophet import Prophet
import pandas as pd
import numpy as np
from sklearn.metrics import mean_absolute_error, mean_squared_error
import warnings
warnings.filterwarnings('ignore')

class TimeSeriesForecaster:
    def __init__(self, prometheus_client):
        self.prometheus = prometheus_client
        self.models = {}
        
    def prepare_prophet_data(self, prometheus_data):
        """Prophet 형식으로 데이터 변환"""
        data_points = []
        
        for result in prometheus_data['data']['result']:
            values = result['values']
            
            for timestamp, value in values:
                if value != 'NaN':
                    data_points.append({
                        'ds': pd.to_datetime(float(timestamp), unit='s'),
                        'y': float(value)
                    })
        
        df = pd.DataFrame(data_points)
        return df.sort_values('ds').reset_index(drop=True)
    
    def train_prophet_model(self, metric_name, query, training_hours=720):  # 30일
        """Prophet 모델 훈련"""
        end_time = time.time()
        start_time = end_time - (training_hours * 3600)
        
        # 훈련 데이터 수집
        training_data = self.prometheus.query_range(
            query=query,
            start=start_time,
            end=end_time,
            step='5m'
        )
        
        # Prophet 형식으로 변환
        df = self.prepare_prophet_data(training_data)
        
        if len(df) < 100:
            raise ValueError(f"훈련 데이터 부족: {len(df)} 포인트")
        
        # Prophet 모델 설정
        model = Prophet(
            daily_seasonality=True,
            weekly_seasonality=True,
            yearly_seasonality=False,
            changepoint_prior_scale=0.05,
            seasonality_prior_scale=10.0,
            interval_width=0.95
        )
        
        # 추가 회귀 변수 (선택적)
        # model.add_regressor('holiday')
        # model.add_regressor('special_event')
        
        # 모델 훈련
        model.fit(df)
        
        # 모델 저장
        self.models[metric_name] = {
            'model': model,
            'query': query,
            'last_trained': time.time(),
            'training_data_size': len(df)
        }
        
        return model
    
    def predict_future(self, metric_name, prediction_hours=24):
        """미래 값 예측"""
        if metric_name not in self.models:
            raise ValueError(f"훈련되지 않은 모델: {metric_name}")
        
        model_info = self.models[metric_name]
        model = model_info['model']
        
        # 미래 시간 프레임 생성
        future_periods = int(prediction_hours * 12)  # 5분 간격
        future = model.make_future_dataframe(periods=future_periods, freq='5T')
        
        # 예측 수행
        forecast = model.predict(future)
        
        # 예측 결과 처리
        prediction_results = {
            'timestamp': forecast['ds'].tail(future_periods),
            'predicted': forecast['yhat'].tail(future_periods),
            'lower_bound': forecast['yhat_lower'].tail(future_periods),
            'upper_bound': forecast['yhat_upper'].tail(future_periods),
            'trend': forecast['trend'].tail(future_periods)
        }
        
        return prediction_results
    
    def detect_forecast_anomalies(self, metric_name, current_value, tolerance=2.0):
        """예측값과 실제값 비교를 통한 이상 감지"""
        if metric_name not in self.models:
            return None
        
        # 현재 시점 예측
        prediction = self.predict_future(metric_name, prediction_hours=0.1)
        
        if len(prediction['predicted']) == 0:
            return None
        
        predicted_value = prediction['predicted'].iloc[-1]
        lower_bound = prediction['lower_bound'].iloc[-1]
        upper_bound = prediction['upper_bound'].iloc[-1]
        
        # 이상 감지 로직
        is_anomaly = (current_value < lower_bound) or (current_value > upper_bound)
        
        # 편차 계산
        if predicted_value != 0:
            deviation_percent = abs(current_value - predicted_value) / abs(predicted_value) * 100
        else:
            deviation_percent = 0
        
        return {
            'is_anomaly': is_anomaly,
            'current_value': current_value,
            'predicted_value': predicted_value,
            'lower_bound': lower_bound,
            'upper_bound': upper_bound,
            'deviation_percent': deviation_percent,
            'confidence_interval': upper_bound - lower_bound
        }

# ARIMA 모델 구현
class ARIMAForecaster:
    def __init__(self):
        from statsmodels.tsa.arima.model import ARIMA
        self.ARIMA = ARIMA
        self.models = {}
        
    def find_optimal_order(self, data, max_p=5, max_d=2, max_q=5):
        """최적 ARIMA 파라미터 찾기"""
        import itertools
        from statsmodels.tsa.stattools import adfuller
        
        # AIC 기반 최적 파라미터 탐색
        best_aic = float('inf')
        best_order = None
        
        # p, d, q 조합 생성
        pdq_combinations = list(itertools.product(
            range(0, max_p + 1),
            range(0, max_d + 1), 
            range(0, max_q + 1)
        ))
        
        for order in pdq_combinations:
            try:
                model = self.ARIMA(data, order=order)
                fitted_model = model.fit()
                
                if fitted_model.aic < best_aic:
                    best_aic = fitted_model.aic
                    best_order = order
                    
            except Exception:
                continue
        
        return best_order, best_aic
    
    def train_arima_model(self, metric_name, data, order=None):
        """ARIMA 모델 훈련"""
        if order is None:
            order, aic = self.find_optimal_order(data)
            print(f"최적 ARIMA 파라미터: {order}, AIC: {aic}")
        
        try:
            model = self.ARIMA(data, order=order)
            fitted_model = model.fit()
            
            self.models[metric_name] = {
                'model': fitted_model,
                'order': order,
                'aic': fitted_model.aic,
                'last_trained': time.time()
            }
            
            return fitted_model
            
        except Exception as e:
            print(f"ARIMA 모델 훈련 실패: {e}")
            return None
    
    def forecast_arima(self, metric_name, steps=24):
        """ARIMA 예측"""
        if metric_name not in self.models:
            raise ValueError(f"훈련되지 않은 모델: {metric_name}")
        
        model = self.models[metric_name]['model']
        
        # 예측 수행
        forecast_result = model.forecast(steps=steps)
        confidence_intervals = model.get_forecast(steps=steps).conf_int()
        
        return {
            'forecast': forecast_result,
            'lower_bound': confidence_intervals.iloc[:, 0],
            'upper_bound': confidence_intervals.iloc[:, 1]
        }
```

### 1.3 딥러닝 기반 이상 감지

**Autoencoder를 이용한 이상 감지**
```python
# deep_anomaly_detection.py
import tensorflow as tf
from tensorflow.keras import layers, Model
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, MinMaxScaler

class AutoencoderAnomalyDetector:
    def __init__(self, input_dim, encoding_dim=32, contamination=0.1):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.contamination = contamination
        self.model = None
        self.scaler = StandardScaler()
        self.threshold = None
        
    def build_autoencoder(self):
        """Autoencoder 모델 구축"""
        # 인코더
        input_layer = layers.Input(shape=(self.input_dim,))
        encoded = layers.Dense(64, activation='relu')(input_layer)
        encoded = layers.Dropout(0.2)(encoded)
        encoded = layers.Dense(self.encoding_dim, activation='relu')(encoded)
        
        # 디코더
        decoded = layers.Dense(64, activation='relu')(encoded)
        decoded = layers.Dropout(0.2)(decoded)
        decoded = layers.Dense(self.input_dim, activation='sigmoid')(decoded)
        
        # 모델 생성
        autoencoder = Model(input_layer, decoded)
        autoencoder.compile(
            optimizer='adam',
            loss='mse',
            metrics=['mae']
        )
        
        self.model = autoencoder
        return autoencoder
    
    def prepare_sequences(self, data, sequence_length=60):
        """시계열 데이터를 시퀀스로 변환"""
        sequences = []
        
        for i in range(len(data) - sequence_length + 1):
            sequence = data[i:i + sequence_length]
            sequences.append(sequence)
            
        return np.array(sequences)
    
    def train(self, training_data, epochs=100, batch_size=32, validation_split=0.2):
        """Autoencoder 훈련"""
        # 데이터 정규화
        normalized_data = self.scaler.fit_transform(training_data)
        
        # 모델 훈련
        history = self.model.fit(
            normalized_data, normalized_data,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            shuffle=True,
            verbose=1,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=10,
                    restore_best_weights=True
                ),
                tf.keras.callbacks.ReduceLROnPlateau(
                    monitor='val_loss',
                    factor=0.5,
                    patience=5,
                    min_lr=1e-7
                )
            ]
        )
        
        # 임계값 계산
        reconstructions = self.model.predict(normalized_data)
        reconstruction_errors = np.mean(np.square(normalized_data - reconstructions), axis=1)
        self.threshold = np.percentile(reconstruction_errors, (1 - self.contamination) * 100)
        
        return history
    
    def detect_anomalies(self, test_data):
        """이상 감지 수행"""
        # 데이터 정규화
        normalized_data = self.scaler.transform(test_data)
        
        # 재구성
        reconstructions = self.model.predict(normalized_data)
        
        # 재구성 오류 계산
        reconstruction_errors = np.mean(np.square(normalized_data - reconstructions), axis=1)
        
        # 이상 감지
        anomalies = reconstruction_errors > self.threshold
        
        return {
            'anomalies': anomalies,
            'reconstruction_errors': reconstruction_errors,
            'threshold': self.threshold,
            'anomaly_scores': reconstruction_errors / self.threshold
        }

# LSTM Autoencoder for Time Series
class LSTMAnomalyDetector:
    def __init__(self, sequence_length=60, n_features=1):
        self.sequence_length = sequence_length
        self.n_features = n_features
        self.model = None
        self.scaler = MinMaxScaler()
        self.threshold = None
        
    def build_lstm_autoencoder(self, lstm_units=50):
        """LSTM Autoencoder 구축"""
        model = tf.keras.Sequential([
            # 인코더
            layers.LSTM(lstm_units, return_sequences=True, input_shape=(self.sequence_length, self.n_features)),
            layers.Dropout(0.2),
            layers.LSTM(lstm_units//2, return_sequences=False),
            layers.Dropout(0.2),
            layers.RepeatVector(self.sequence_length),
            
            # 디코더
            layers.LSTM(lstm_units//2, return_sequences=True),
            layers.Dropout(0.2),
            layers.LSTM(lstm_units, return_sequences=True),
            layers.TimeDistributed(layers.Dense(self.n_features))
        ])
        
        model.compile(optimizer='adam', loss='mse')
        self.model = model
        return model
    
    def prepare_lstm_data(self, data):
        """LSTM용 데이터 준비"""
        # 데이터 정규화
        scaled_data = self.scaler.fit_transform(data.reshape(-1, 1))
        
        # 시퀀스 생성
        sequences = []
        for i in range(len(scaled_data) - self.sequence_length + 1):
            sequences.append(scaled_data[i:i + self.sequence_length])
            
        return np.array(sequences)
    
    def train_lstm(self, training_data, epochs=50, batch_size=32):
        """LSTM Autoencoder 훈련"""
        sequences = self.prepare_lstm_data(training_data)
        
        history = self.model.fit(
            sequences, sequences,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,
            verbose=1,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=10,
                    restore_best_weights=True
                )
            ]
        )
        
        # 임계값 설정
        predictions = self.model.predict(sequences)
        mse = np.mean(np.power(sequences - predictions, 2), axis=(1, 2))
        self.threshold = np.percentile(mse, 95)
        
        return history
    
    def detect_lstm_anomalies(self, test_data):
        """LSTM 기반 이상 감지"""
        sequences = self.prepare_lstm_data(test_data)
        predictions = self.model.predict(sequences)
        
        # MSE 계산
        mse = np.mean(np.power(sequences - predictions, 2), axis=(1, 2))
        
        # 이상 감지
        anomalies = mse > self.threshold
        
        return {
            'anomalies': anomalies,
            'mse_scores': mse,
            'threshold': self.threshold,
            'anomaly_indices': np.where(anomalies)[0]
        }
```

## 2. 예측 분석 (Predictive Analytics)

### 2.1 용량 계획 및 성능 저하 예측

**용량 계획 시스템**
```python
# capacity_planning.py
import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, r2_score
import matplotlib.pyplot as plt

class CapacityPlanner:
    def __init__(self, prometheus_client):
        self.prometheus = prometheus_client
        self.models = {}
        self.capacity_thresholds = {
            'cpu': 80,
            'memory': 85,
            'disk': 90,
            'network': 80
        }
        
    def collect_capacity_data(self, metric_queries, days=30):
        """용량 관련 데이터 수집"""
        end_time = time.time()
        start_time = end_time - (days * 24 * 3600)
        
        capacity_data = {}
        
        for resource_type, query in metric_queries.items():
            try:
                result = self.prometheus.query_range(
                    query=query,
                    start=start_time,
                    end=end_time,
                    step='1h'
                )
                
                # 데이터 변환
                df = self._prometheus_to_dataframe(result)
                capacity_data[resource_type] = df
                
            except Exception as e:
                print(f"데이터 수집 실패 {resource_type}: {e}")
                
        return capacity_data
    
    def train_capacity_models(self, capacity_data):
        """용량 예측 모델 훈련"""
        for resource_type, df in capacity_data.items():
            if len(df) < 100:  # 최소 데이터 요구사항
                continue
                
            # 특성 엔지니어링
            features = self._extract_capacity_features(df)
            target = df['value'].values
            
            # 여러 모델 훈련 및 비교
            models = {
                'linear': LinearRegression(),
                'random_forest': RandomForestRegressor(n_estimators=100, random_state=42)
            }
            
            best_model = None
            best_score = -float('inf')
            
            for model_name, model in models.items():
                try:
                    # 훈련/테스트 분할
                    split_idx = int(len(features) * 0.8)
                    X_train, X_test = features[:split_idx], features[split_idx:]
                    y_train, y_test = target[:split_idx], target[split_idx:]
                    
                    # 모델 훈련
                    model.fit(X_train, y_train)
                    
                    # 평가
                    predictions = model.predict(X_test)
                    score = r2_score(y_test, predictions)
                    
                    if score > best_score:
                        best_score = score
                        best_model = model
                        
                except Exception as e:
                    print(f"모델 훈련 실패 {model_name}: {e}")
                    continue
            
            if best_model is not None:
                self.models[resource_type] = {
                    'model': best_model,
                    'score': best_score,
                    'last_trained': time.time()
                }
                print(f"{resource_type} 용량 모델 훈련 완료 (R²: {best_score:.3f})")
    
    def predict_capacity_exhaustion(self, resource_type, prediction_days=30):
        """용량 고갈 시점 예측"""
        if resource_type not in self.models:
            return None
            
        model_info = self.models[resource_type]
        model = model_info['model']
        
        # 최근 데이터로 미래 예측
        current_time = time.time()
        future_timestamps = [
            current_time + (i * 3600) for i in range(prediction_days * 24)
        ]
        
        # 미래 특성 생성
        future_features = self._generate_future_features(future_timestamps)
        
        # 예측 수행
        predictions = model.predict(future_features)
        
        # 임계값 초과 시점 찾기
        threshold = self.capacity_thresholds.get(resource_type, 80)
        exhaustion_points = []
        
        for i, prediction in enumerate(predictions):
            if prediction > threshold:
                exhaustion_time = future_timestamps[i]
                exhaustion_points.append({
                    'timestamp': exhaustion_time,
                    'predicted_value': prediction,
                    'days_until_exhaustion': i / 24
                })
                break
        
        return {
            'resource_type': resource_type,
            'threshold': threshold,
            'predictions': predictions,
            'timestamps': future_timestamps,
            'exhaustion_points': exhaustion_points,
            'model_score': model_info['score']
        }
    
    def generate_capacity_report(self):
        """용량 계획 보고서 생성"""
        report = {
            'generation_time': time.time(),
            'resources': {},
            'recommendations': [],
            'alerts': []
        }
        
        for resource_type in self.models.keys():
            prediction = self.predict_capacity_exhaustion(resource_type)
            
            if prediction and prediction['exhaustion_points']:
                exhaustion_point = prediction['exhaustion_points'][0]
                days_until = exhaustion_point['days_until_exhaustion']
                
                report['resources'][resource_type] = {
                    'current_usage': self._get_current_usage(resource_type),
                    'predicted_exhaustion': exhaustion_point,
                    'trend': 'increasing' if days_until < 90 else 'stable'
                }
                
                # 권장사항 생성
                if days_until < 7:
                    report['alerts'].append(f"{resource_type} 용량 부족 임박 ({days_until:.1f}일)")
                    report['recommendations'].append(f"즉시 {resource_type} 용량 확장 필요")
                elif days_until < 30:
                    report['recommendations'].append(f"{resource_type} 용량 확장 계획 수립 권장")
                    
        return report
    
    def _extract_capacity_features(self, df):
        """용량 예측을 위한 특성 추출"""
        features = []
        
        for i in range(len(df)):
            # 시간 기반 특성
            timestamp = df.iloc[i]['timestamp']
            dt = pd.to_datetime(timestamp, unit='s')
            
            feature_vector = [
                timestamp,  # 절대 시간
                dt.hour,    # 시간
                dt.dayofweek,  # 요일
                dt.day,     # 일
                dt.month    # 월
            ]
            
            # 통계적 특성 (이동 평균, 트렌드 등)
            if i >= 24:  # 24시간 이상 데이터가 있을 때
                recent_values = df.iloc[i-24:i]['value'].values
                feature_vector.extend([
                    np.mean(recent_values),
                    np.std(recent_values),
                    np.max(recent_values),
                    np.min(recent_values)
                ])
            else:
                feature_vector.extend([0, 0, 0, 0])
                
            features.append(feature_vector)
            
        return np.array(features)
```

### 2.2 근본 원인 분석 자동화

**인과관계 분석 시스템**
```python
# root_cause_analysis.py
import networkx as nx
import pandas as pd
from sklearn.feature_selection import mutual_info_regression
from scipy.stats import pearsonr
import numpy as np

class RootCauseAnalyzer:
    def __init__(self, prometheus_client):
        self.prometheus = prometheus_client
        self.dependency_graph = nx.DiGraph()
        self.correlation_matrix = {}
        self.causal_models = {}
        
    def build_service_dependency_graph(self, services_config):
        """서비스 의존성 그래프 구축"""
        for service, config in services_config.items():
            self.dependency_graph.add_node(service, **config)
            
            # 의존성 추가
            for dependency in config.get('dependencies', []):
                self.dependency_graph.add_edge(dependency, service)
                
    def analyze_incident_correlation(self, incident_time, analysis_window=3600):
        """인시던트 시점 주변의 상관관계 분석"""
        start_time = incident_time - analysis_window
        end_time = incident_time + analysis_window
        
        # 주요 메트릭 수집
        metrics_queries = {
            'cpu_usage': 'avg(rate(container_cpu_usage_seconds_total[5m])) by (pod)',
            'memory_usage': 'avg(container_memory_usage_bytes) by (pod)',
            'error_rate': 'rate(http_requests_total{status=~"5.."}[5m])',
            'response_time': 'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))',
            'network_errors': 'rate(container_network_receive_errors_total[5m])',
            'disk_io': 'rate(container_fs_reads_total[5m]) + rate(container_fs_writes_total[5m])'
        }
        
        metric_data = {}
        for metric_name, query in metrics_queries.items():
            try:
                result = self.prometheus.query_range(
                    query=query,
                    start=start_time,
                    end=end_time,
                    step='1m'
                )
                metric_data[metric_name] = self._process_metric_data(result)
            except Exception as e:
                print(f"메트릭 수집 실패 {metric_name}: {e}")
                
        # 상관관계 분석
        correlations = self._calculate_correlations(metric_data)
        
        # 인과관계 추론
        causal_chains = self._infer_causal_chains(correlations, incident_time)
        
        return {
            'incident_time': incident_time,
            'correlations': correlations,
            'causal_chains': causal_chains,
            'root_cause_candidates': self._rank_root_causes(causal_chains)
        }
    
    def _calculate_correlations(self, metric_data):
        """메트릭 간 상관관계 계산"""
        correlations = {}
        metric_names = list(metric_data.keys())
        
        for i in range(len(metric_names)):
            for j in range(i + 1, len(metric_names)):
                metric1, metric2 = metric_names[i], metric_names[j]
                
                if metric1 in metric_data and metric2 in metric_data:
                    data1 = metric_data[metric1]
                    data2 = metric_data[metric2]
                    
                    # 시간 정렬
                    aligned_data = self._align_time_series(data1, data2)
                    
                    if len(aligned_data) > 10:
                        correlation, p_value = pearsonr(
                            aligned_data[metric1], 
                            aligned_data[metric2]
                        )
                        
                        correlations[f"{metric1}-{metric2}"] = {
                            'correlation': correlation,
                            'p_value': p_value,
                            'significant': p_value < 0.05,
                            'strength': abs(correlation)
                        }
        
        return correlations
    
    def _infer_causal_chains(self, correlations, incident_time):
        """인과관계 체인 추론"""
        causal_chains = []
        
        # 시간 지연 기반 인과관계 분석
        for correlation_key, correlation_data in correlations.items():
            if correlation_data['significant'] and correlation_data['strength'] > 0.3:
                metric1, metric2 = correlation_key.split('-')
                
                # 시간 지연 분석
                time_lag = self._calculate_time_lag(metric1, metric2, incident_time)
                
                if time_lag > 0:  # metric1이 metric2보다 앞서 변화
                    causal_chains.append({
                        'cause': metric1,
                        'effect': metric2,
                        'correlation': correlation_data['correlation'],
                        'time_lag_minutes': time_lag,
                        'confidence': correlation_data['strength']
                    })
        
        return sorted(causal_chains, key=lambda x: x['confidence'], reverse=True)
    
    def _rank_root_causes(self, causal_chains):
        """근본 원인 후보 순위 매기기"""
        cause_scores = {}
        
        for chain in causal_chains:
            cause = chain['cause']
            effect = chain['effect']
            confidence = chain['confidence']
            
            # 원인이 되는 메트릭에 점수 부여
            if cause not in cause_scores:
                cause_scores[cause] = 0
            cause_scores[cause] += confidence
            
            # 다른 원인의 영향을 받는 메트릭은 점수 감소
            if effect in cause_scores:
                cause_scores[effect] -= confidence * 0.5
        
        # 서비스 의존성 그래프 고려
        for cause, score in cause_scores.items():
            # 상위 서비스(의존성이 많은)에 가중치 부여
            if self.dependency_graph.has_node(cause):
                in_degree = self.dependency_graph.in_degree(cause)
                cause_scores[cause] *= (1 + in_degree * 0.1)
        
        # 점수 순으로 정렬
        ranked_causes = sorted(
            cause_scores.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        return [
            {
                'metric': cause,
                'root_cause_score': score,
                'likelihood': min(score / max(cause_scores.values()) * 100, 100)
            }
            for cause, score in ranked_causes[:5]  # 상위 5개만
        ]
    
    def generate_rca_report(self, incident_time, incident_description=""):
        """근본 원인 분석 보고서 생성"""
        analysis = self.analyze_incident_correlation(incident_time)
        
        report = {
            'incident_summary': {
                'time': incident_time,
                'description': incident_description,
                'analysis_timestamp': time.time()
            },
            'root_cause_analysis': analysis,
            'recommended_actions': [],
            'investigation_steps': []
        }
        
        # 권장 조치 생성
        top_causes = analysis['root_cause_candidates'][:3]
        
        for cause in top_causes:
            metric = cause['metric']
            likelihood = cause['likelihood']
            
            if metric == 'cpu_usage' and likelihood > 70:
                report['recommended_actions'].extend([
                    "CPU 사용률이 높은 프로세스 식별",
                    "수평/수직 스케일링 고려",
                    "애플리케이션 프로파일링 수행"
                ])
            elif metric == 'memory_usage' and likelihood > 70:
                report['recommended_actions'].extend([
                    "메모리 누수 확인",
                    "가비지 컬렉션 튜닝",
                    "메모리 덤프 분석"
                ])
            elif metric == 'error_rate' and likelihood > 70:
                report['recommended_actions'].extend([
                    "에러 로그 상세 분석",
                    "최근 배포 변경사항 확인",
                    "의존성 서비스 상태 점검"
                ])
        
        # 조사 단계 제안
        report['investigation_steps'] = [
            f"1. {top_causes[0]['metric']} 메트릭 상세 분석",
            "2. 해당 시점의 시스템 이벤트 로그 확인",
            "3. 관련 서비스의 의존성 체크",
            "4. 인프라 레벨 이벤트 확인",
            "5. 애플리케이션 로그 분석"
        ]
        
        return report

# 이상 패턴 탐지 시스템
class AnomalyPatternDetector:
    def __init__(self):
        self.known_patterns = {
            'memory_leak': {
                'metrics': ['memory_usage'],
                'pattern': 'gradual_increase',
                'duration': 3600,  # 1시간
                'threshold': 0.8
            },
            'cpu_spike': {
                'metrics': ['cpu_usage'],
                'pattern': 'sudden_spike',
                'duration': 300,   # 5분
                'threshold': 0.9
            },
            'cascading_failure': {
                'metrics': ['error_rate', 'response_time'],
                'pattern': 'sequential_degradation',
                'duration': 600,   # 10분
                'correlation_threshold': 0.7
            }
        }
    
    def detect_pattern(self, metric_data, pattern_name):
        """특정 패턴 탐지"""
        if pattern_name not in self.known_patterns:
            return None
            
        pattern_config = self.known_patterns[pattern_name]
        
        if pattern_config['pattern'] == 'gradual_increase':
            return self._detect_gradual_increase(metric_data, pattern_config)
        elif pattern_config['pattern'] == 'sudden_spike':
            return self._detect_sudden_spike(metric_data, pattern_config)
        elif pattern_config['pattern'] == 'sequential_degradation':
            return self._detect_sequential_degradation(metric_data, pattern_config)
            
        return None
    
    def _detect_gradual_increase(self, metric_data, config):
        """점진적 증가 패턴 탐지"""
        window_size = config['duration'] // 60  # 분 단위로 변환
        threshold = config['threshold']
        
        if len(metric_data) < window_size:
            return None
            
        # 이동 평균 계산
        moving_avg = pd.Series(metric_data).rolling(window=window_size).mean()
        
        # 기울기 계산
        x = np.arange(len(moving_avg))
        slope = np.polyfit(x, moving_avg.dropna(), 1)[0]
        
        # 패턴 탐지
        if slope > 0 and moving_avg.iloc[-1] > threshold:
            return {
                'pattern_detected': True,
                'pattern_type': 'gradual_increase',
                'slope': slope,
                'final_value': moving_avg.iloc[-1],
                'confidence': min(slope * 100, 1.0)
            }
            
        return {'pattern_detected': False}
```

## 3. 실습 과제

### 과제 1: 이상 감지 시스템 구축
1. Prophet 기반 시계열 예측 모델 구현
2. Autoencoder를 이용한 멀티변수 이상 감지
3. 실시간 이상 탐지 대시보드 구축

### 과제 2: 용량 계획 시스템 개발
1. 리소스별 용량 예측 모델 훈련
2. 용량 고갈 시점 예측 시스템
3. 자동화된 용량 계획 보고서 생성

### 과제 3: 근본 원인 분석 자동화
1. 서비스 의존성 그래프 구축
2. 인시던트 상관관계 분석 시스템
3. 자동화된 RCA 보고서 생성

## 4. 성능 최적화

### 모델 성능 메트릭
```python
# 이상 감지 정확도
precision = true_positives / (true_positives + false_positives)
recall = true_positives / (true_positives + false_negatives)
f1_score = 2 * (precision * recall) / (precision + recall)

# 예측 정확도
mae = mean_absolute_error(y_true, y_pred)
mse = mean_squared_error(y_true, y_pred)
mape = mean_absolute_percentage_error(y_true, y_pred)
```

## 5. 다음 단계
- 애플리케이션 성능 모니터링 (Phase 4-1)
- 로그 관리 및 분석 (Phase 4-2)